import test from 'node:test'
import assert from 'node:assert/strict'
import { createCsrfProtection } from '../src/security/csrf.js'
import { createSessionService } from '../src/modules/auth/session.service.js'

// ข้อมูลสมมติสำหรับ tests เท่านั้น
const userId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const fixedTime = Date.parse('2026-11-02T03:00:00.987Z')

function createFixture({
  now = () => fixedTime,
  databaseError,
  findActiveSession = async () => null,
} = {}) {
  const writes = []
  const csrfProtection = createCsrfProtection('11'.repeat(32))

  const sessionRepository = {
    findActiveSession,

    async createSession(input) {
      writes.push(input)

      if (databaseError) {
        throw databaseError
      }

      return {
        session_id: input.sessionId,
        user_id: input.userId,
        expires_at: input.expiresAt,
        csrf_token_hash: input.csrfTokenHash,
        revoked_at: null,
      }
    },
  }

  const service = createSessionService({
    sessionRepository,
    csrfProtection,
    now,
  })

  return { service, writes, csrfProtection }
}

test('creates a session with a digest, expiry and limited return fields', async () => {
  const { service, writes, csrfProtection } = createFixture()

  const result = await service.startSession({ userId })

  assert.equal(writes.length, 1)

  const saved = writes[0]

  assert.match(
    saved.sessionId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
  )
  assert.equal(saved.userId, userId)

  // เวลาเริ่มถูกปัดลงเป็นวินาที แล้วเพิ่มอีก 30 นาที
  assert.equal(
    saved.expiresAt.toISOString(),
    '2026-11-02T03:30:00.000Z'
  )

  const token = csrfProtection.createToken({
    sessionId: saved.sessionId,
    userId,
  })

  assert.equal(saved.csrfTokenHash, csrfProtection.hashToken(token))

  // Repository ต้องได้รับเฉพาะข้อมูลที่ใช้บันทึก
  assert.deepEqual(Object.keys(saved).sort(), [
    'csrfTokenHash',
    'expiresAt',
    'sessionId',
    'userId',
  ])

  // Service ต้องไม่คืน digest หรือข้อมูลภายในอื่นออกมา
  assert.deepEqual(result, {
    sessionId: saved.sessionId,
    userId,
    expiresAt: saved.expiresAt,
  })
})

test('creates a different session and digest for each login', async () => {
  const { service, writes } = createFixture()

  const first = await service.startSession({ userId })
  const second = await service.startSession({ userId })

  assert.equal(writes.length, 2)
  assert.notEqual(first.sessionId, second.sessionId)
  assert.notEqual(writes[0].csrfTokenHash, writes[1].csrfTokenHash)
})

test('rejects invalid user identifiers before writing', async () => {
  const { service, writes } = createFixture()

  for (const invalid of [undefined, null, 123, '', 'student_demo']) {
    await assert.rejects(
      service.startSession({ userId: invalid }),
      TypeError
    )
  }

  assert.equal(writes.length, 0)
})

test('rejects invalid clock values before writing', async () => {
  const invalidTimes = [
    NaN,
    Infinity,
    -1,
    1.5,
    '0',
    Number.MAX_SAFE_INTEGER,
  ]

  for (const invalidTime of invalidTimes) {
    const { service, writes } = createFixture({
      now: () => invalidTime,
    })

    await assert.rejects(
      service.startSession({ userId }),
      TypeError
    )

    assert.equal(writes.length, 0)
  }
})

test('propagates repository failure instead of returning success', async () => {
  const databaseError = new Error('Simulated database failure')
  const { service, writes } = createFixture({ databaseError })

  await assert.rejects(
    service.startSession({ userId }),
    (error) => error === databaseError
  )

  assert.equal(writes.length, 1)
})

const sessionContext = {
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  userId,
}

const sessionProtection = createCsrfProtection('11'.repeat(32))
const expectedToken = sessionProtection.createToken(sessionContext)

const activeSessionRow = {
  session_id: sessionContext.sessionId,
  user_id: userId,
  csrf_token_hash: sessionProtection.hashToken(expectedToken),
}

test('rejects missing or invalid repository dependencies', () => {
  const validRepository = {
    createSession: async () => null,
    findActiveSession: async () => null,
  }

  function expectRejected(sessionRepository) {
    assert.throws(() => createSessionService({
      sessionRepository,
      csrfProtection: sessionProtection,
    }), {
      name: 'TypeError',
      message: 'A session repository is required',
    })
  }

  for (const invalid of [undefined, null, {}]) {
    expectRejected(invalid)
  }

  for (const method of ['createSession', 'findActiveSession']) {
    for (const invalid of [undefined, 123]) {
      expectRejected({ ...validRepository, [method]: invalid })
    }
  }
})

test('rejects missing or invalid CSRF dependencies', () => {
  const sessionRepository = {
    createSession: async () => null,
    findActiveSession: async () => null,
  }

  function expectRejected(csrfProtection) {
    assert.throws(() => createSessionService({
      sessionRepository,
      csrfProtection,
    }), {
      name: 'TypeError',
      message: 'CSRF protection is required',
    })
  }

  for (const invalid of [undefined, null, {}]) {
    expectRejected(invalid)
  }

  for (const method of ['createToken', 'hashToken', 'verifyToken']) {
    for (const invalid of [undefined, 123]) {
      expectRejected({ ...sessionProtection, [method]: invalid })
    }
  }
})

test('returns the same CSRF token for an active session', async () => {
  const { service } = createFixture({
    findActiveSession: async (lookup) => {
      assert.deepEqual(lookup, sessionContext)
      return activeSessionRow
    },
  })

  assert.equal(
    await service.getCsrfToken(sessionContext),
    expectedToken
  )
  assert.equal(
    await service.getCsrfToken(sessionContext),
    expectedToken
  )
})

test('returns no CSRF token when there is no active session', async () => {
  const { service } = createFixture()

  assert.equal(
    await service.getCsrfToken(sessionContext),
    null
  )
})

test('rejects a mismatched digest or a token from an old key', async () => {
  const oldProtection = createCsrfProtection('22'.repeat(32))
  const oldToken = oldProtection.createToken(sessionContext)

  const invalidRows = [
    {
      ...activeSessionRow,
      csrf_token_hash: '0'.repeat(64),
    },
    {
      ...activeSessionRow,
      csrf_token_hash: oldProtection.hashToken(oldToken),
    },
  ]

  for (const row of invalidRows) {
    const { service } = createFixture({
      findActiveSession: async () => row,
    })

    assert.equal(
      await service.getCsrfToken(sessionContext),
      null
    )
  }
})

test('propagates session lookup failure instead of returning a token', async () => {
  const databaseError = new Error('Simulated session lookup failure')

  const { service } = createFixture({
    findActiveSession: async () => {
      throw databaseError
    },
  })

  await assert.rejects(
    service.getCsrfToken(sessionContext),
    (error) => error === databaseError
  )
})
