import test from 'node:test'
import assert from 'node:assert/strict'
import { once, EventEmitter } from 'node:events'
import { request as httpRequest } from 'node:http'
import { gzipSync } from 'node:zlib'
import express from 'express'
import { createRoleChangeRouter } from '../src/modules/roles/role-change.routes.js'
import { createRoleChangeService } from '../src/modules/roles/role-change.service.js'
import { createRoleChangeRuntimeRepository } from '../src/modules/roles/role-change.runtime.repository.js'
import { createAuthorizationService } from '../src/modules/authorization/authorization.service.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { createSessionService } from '../src/modules/auth/session.service.js'
import { createSessionAuthService } from '../src/modules/auth/session-auth.service.js'
import { createJwtService } from '../src/security/jwt.js'
import { createCsrfProtection } from '../src/security/csrf.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

const ORIGIN = 'http://localhost:5173'
const PATH = '/api/v1/admin/role-changes'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const AUDIT = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
const actors = {
  admin: {
    userId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    sessionId: '11111111-1111-4111-8111-111111111111',
  },
  student: {
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    sessionId: '22222222-2222-4222-8222-222222222222',
  },
  faculty: {
    userId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    sessionId: '33333333-3333-4333-8333-333333333333',
  },
}
const INPUT = {
  targetUserId: actors.student.userId,
  roleCode: 'advisor',
  action: 'assign',
  reason: 'มอบหมายอาจารย์ที่ปรึกษา',
}

// ทดสอบ HTTP/router/crypto/services/runtime จริงกับ session/role/PG client จำลอง
// ไม่อ่าน .env และไม่เชื่อมฐานข้อมูลจริง
async function fixture(t, options = {}) {
  const stats = {
    auth: 0,
    sessions: 0,
    roles: [],
    csrf: 0,
    transactions: 0,
    mutations: [],
    queries: [],
    releases: [],
    logs: [],
  }
  let now = Date.parse('2026-11-04T04:00:00Z')
  const expiresAt = new Date(now + 1800 * 1000)
  const jwtService = createJwtService({ secretHex: '11'.repeat(32), now: () => now })
  const csrfProtection = createCsrfProtection('22'.repeat(32))
  const csrf = {}
  const tokens = {}
  const rows = []
  for (const [name, identity] of Object.entries(actors)) {
    tokens[name] = await jwtService.signSession({ ...identity, expiresAt })
    csrf[name] = csrfProtection.createToken(identity)
    rows.push({
      session_id: identity.sessionId,
      user_id: identity.userId,
      expires_at: expiresAt,
      username: name + '_demo',
      display_name: name,
      csrf_token_hash: csrfProtection.hashToken(csrf[name]),
    })
  }
  const sessionRepository = {
    async createSession() {
      assert.fail('Role changes must not create a login session')
    },
    async findActiveSession({ sessionId, userId }) {
      stats.sessions += 1
      if (options.sessionError) throw options.sessionError
      if (options.rejectSession || (options.rejectAtCsrf && stats.sessions > 1))
        return null
      return (
        rows.find((row) => row.session_id === sessionId && row.user_id === userId) ?? null
      )
    },
  }
  const sessionAuthService = createSessionAuthService({ jwtService, sessionRepository })
  const requireSession = createRequireSession({
    sessionCookie: createSessionCookie({
      name: 'p32_session_dev',
      options: { httpOnly: true, secure: false, sameSite: 'lax', path: '/' },
    }),
    sessionAuthService: {
      async authenticateSessionToken(token) {
        stats.auth += 1
        return sessionAuthService.authenticateSessionToken(token)
      },
    },
  })
  const authorizationService = createAuthorizationService({
    authorizationRepository: {
      async findRoleCodesByUserId(userId) {
        stats.roles.push(userId)
        if (options.roleError) throw options.roleError
        return userId === actors.admin.userId
          ? ['system_admin']
          : userId === actors.faculty.userId
            ? ['advisor', 'course_manager']
            : ['student']
      },
    },
  })
  const realSessionService = createSessionService({
    sessionRepository,
    csrfProtection,
    now: () => now,
  })
  const sessionService = {
    async getCsrfToken(context) {
      stats.csrf += 1
      return realSessionService.getCsrfToken(context)
    },
  }
  const pool = {
    async connect() {
      stats.transactions += 1
      const client = new EventEmitter()
      client.release = (discard) => stats.releases.push(discard)
      client.query = async (config) => {
        stats.queries.push(config)
        if (config.text.includes('FROM p32.change_user_role')) {
          stats.mutations.push(config.values)
          if (options.mutationError) throw options.mutationError
          const changed = options.changed ?? true
          return {
            rows: [
              { changed, audit_id: changed ? AUDIT : null, hidden: 'PRIVATE_DETAIL' },
            ],
          }
        }
        return { rows: [], command: config.text === 'COMMIT' ? 'COMMIT' : undefined }
      }
      return client
    },
  }
  const roleChangeService = createRoleChangeService({
    roleChangeRepository: createRoleChangeRuntimeRepository(pool),
  })
  const dependencies = {
    webOrigin: ORIGIN,
    requireSession,
    authorizationService,
    sessionService,
    roleChangeService,
  }
  const app = express()
  app.disable('x-powered-by')
  app.use(requestContext)
  app.use(PATH, createRoleChangeRouter(dependencies))
  app.use((request, response) =>
    response
      .set('Cache-Control', 'no-store')
      .status(404)
      .json({
        code: 'NOT_FOUND',
        message: 'ไม่พบเส้นทางที่ร้องขอ',
        request_id: request.requestId,
      }),
  )
  app.use(
    createApiErrorHandler({
      logger: {
        error(...args) {
          stats.logs.push(args)
        },
      },
    }),
  )
  const server = app.listen(0, '127.0.0.1')
  t.after(
    () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  )
  await once(server, 'listening')
  const base = `http://127.0.0.1:${server.address().port}${PATH}`

  async function send({
    actor = 'admin',
    cookie,
    origin = ORIGIN,
    csrfToken,
    contentType = 'application/json',
    body = INPUT,
    raw,
    method = 'POST',
    headers = {},
    query = '',
  } = {}) {
    const data =
      raw === undefined
        ? Buffer.from(JSON.stringify(body))
        : Buffer.isBuffer(raw)
          ? raw
          : Buffer.from(raw)
    const requestHeaders = { 'Content-Length': data.length }
    if (origin !== null) requestHeaders.Origin = origin
    if (contentType !== null) requestHeaders['Content-Type'] = contentType
    if (cookie !== null)
      requestHeaders.Cookie = cookie ?? `p32_session_dev=${tokens[actor]}`
    if (csrfToken !== null) requestHeaders['X-CSRF-Token'] = csrfToken ?? csrf[actor]
    Object.assign(requestHeaders, headers)
    return new Promise((resolve, reject) => {
      const request = httpRequest(
        base + query,
        { method, headers: requestHeaders, agent: false, timeout: 5000 },
        (response) => {
          const chunks = []
          response.on('error', reject)
          response.on('data', (chunk) => chunks.push(chunk))
          response.on('end', () => {
            try {
              const text = Buffer.concat(chunks).toString('utf8')
              resolve({
                status: response.statusCode,
                headers: response.headers,
                body: text ? JSON.parse(text) : null,
              })
            } catch (error) {
              reject(error)
            }
          })
        },
      )
      request.on('error', reject)
      request.on('timeout', () =>
        request.destroy(new Error('Fixture HTTP request timed out')),
      )
      request.end(data)
    })
  }
  return {
    send,
    stats,
    dependencies,
    csrf,
    tokens,
    advance: () => {
      now += 1800 * 1000
    },
  }
}

function assertFailure(result, status, code) {
  assert.equal(result.status, status)
  assert.equal(result.body.code, code)
  assert.deepEqual(Object.keys(result.body).sort(), ['code', 'message', 'request_id'])
  assert.match(result.headers['x-request-id'], UUID)
  assert.equal(result.body.request_id, result.headers['x-request-id'])
  assert.equal(result.headers['cache-control'], 'no-store')
  assert.equal(result.headers['set-cookie'], undefined)
  assert.doesNotMatch(JSON.stringify(result.body), /PRIVATE_DETAIL|SELECT|p32\./)
}

test('admin passes the real session, role, CSRF, validation and transaction chain with server context', async (t) => {
  const { send, stats } = await fixture(t)
  const result = await send({
    body: { ...INPUT, reason: '  มอบหมายอาจารย์ที่ปรึกษา  ' },
    query: `?actorUserId=${actors.student.userId}&role=system_admin`,
    headers: {
      'X-User-Id': actors.student.userId,
      'X-Request-Id': actors.student.userId,
    },
  })
  assert.equal(result.status, 200)
  assert.deepEqual(result.body, { changed: true, auditId: AUDIT })
  assert.equal(result.headers['cache-control'], 'no-store')
  assert.equal(result.headers['set-cookie'], undefined)
  assert.equal(result.headers['x-powered-by'], undefined)
  assert.match(result.headers['x-request-id'], UUID)
  assert.notEqual(result.headers['x-request-id'], actors.student.userId)
  assert.deepEqual(stats.roles, [actors.admin.userId])
  assert.equal(stats.csrf, 1)
  assert.deepEqual(stats.mutations, [
    [
      actors.admin.userId,
      INPUT.targetUserId,
      'advisor',
      'assign',
      INPUT.reason,
      result.headers['x-request-id'],
    ],
  ])
  assert.equal(stats.queries.at(-1).text, 'COMMIT')
  assert.deepEqual(stats.releases, [false])
  assert.deepEqual(stats.logs, [])
})

test('returns a no-op and forwards revoke without changing the request contract', async (t) => {
  const { send, stats } = await fixture(t, { changed: false })
  const result = await send({ body: { ...INPUT, action: 'revoke' } })
  assert.equal(result.status, 200)
  assert.deepEqual(result.body, { changed: false, auditId: null })
  assert.equal(stats.mutations[0][3], 'revoke')
  assert.equal(stats.queries.at(-1).text, 'COMMIT')
})

test('missing or foreign Origin is rejected before session checks and JSON parsing', async (t) => {
  const { send, stats } = await fixture(t)
  for (const origin of [null, 'https://attacker.example', ORIGIN + '.attacker.example'])
    assertFailure(await send({ origin, raw: '{' }), 403, 'ORIGIN_NOT_ALLOWED')
  assert.equal(stats.auth, 0)
  assert.equal(stats.transactions, 0)
})

test('missing and malformed cookies cannot reach roles, CSRF or mutation', async (t) => {
  const { send, stats } = await fixture(t)
  for (const cookie of [null, 'p32_session_dev=invalid'])
    assertFailure(await send({ cookie, raw: '{' }), 401, 'AUTH_REQUIRED')
  assert.equal(stats.roles.length, 0)
  assert.equal(stats.csrf, 0)
  assert.equal(stats.transactions, 0)
})

test('tampered JWTs are rejected before session rows and roles are queried', async (t) => {
  const { send, stats, tokens } = await fixture(t)
  const parts = tokens.admin.split('.')
  parts[2] = (parts[2][0] === 'a' ? 'b' : 'a') + parts[2].slice(1)
  assertFailure(
    await send({ cookie: `p32_session_dev=${parts.join('.')}` }),
    401,
    'AUTH_REQUIRED',
  )
  assert.equal(stats.sessions, 0)
  assert.equal(stats.roles.length, 0)
  assert.equal(stats.transactions, 0)
})

test('expired JWTs and revoked sessions cannot begin role changes', async (t) => {
  const expired = await fixture(t)
  expired.advance()
  assertFailure(await expired.send(), 401, 'AUTH_REQUIRED')
  assert.equal(expired.stats.transactions, 0)
  const revoked = await fixture(t, { rejectSession: true })
  assertFailure(await revoked.send(), 401, 'AUTH_REQUIRED')
  assert.equal(revoked.stats.roles.length, 0)
  assert.equal(revoked.stats.transactions, 0)
})

test('students and multi-role faculty are rejected before CSRF and body parsing', async (t) => {
  const { send, stats } = await fixture(t)
  for (const actor of ['student', 'faculty'])
    assertFailure(
      await send({ actor, raw: '{', headers: { 'X-Role': 'system_admin' } }),
      403,
      'FORBIDDEN',
    )
  assert.equal(stats.csrf, 0)
  assert.equal(stats.transactions, 0)
})

test('missing, malformed and another session CSRF token cannot reach mutation', async (t) => {
  const { send, stats, csrf } = await fixture(t)
  for (const csrfToken of [null, 'invalid', csrf.student])
    assertFailure(await send({ csrfToken, raw: '{' }), 403, 'CSRF_INVALID')
  assert.equal(stats.transactions, 0)
})

test('a session lost between authentication and CSRF checks is rejected', async (t) => {
  const { send, stats } = await fixture(t, { rejectAtCsrf: true })
  assertFailure(await send(), 401, 'AUTH_REQUIRED')
  assert.equal(stats.csrf, 1)
  assert.equal(stats.transactions, 0)
})

test('rejects unsupported media types before calling the mutation service', async (t) => {
  const { send, stats } = await fixture(t)
  for (const contentType of ['text/plain', 'application/x-www-form-urlencoded', null])
    assertFailure(await send({ contentType }), 415, 'UNSUPPORTED_MEDIA_TYPE')
  assert.equal(stats.transactions, 0)
})

test('rejects malformed JSON and scalar bodies before beginning a transaction', async (t) => {
  const { send, stats } = await fixture(t)
  for (const raw of ['{', 'null', '123'])
    assertFailure(await send({ raw }), 400, 'INVALID_JSON')
  assert.equal(stats.transactions, 0)
})

test('rejects oversized JSON and compressed payloads before beginning a transaction', async (t) => {
  const { send, stats } = await fixture(t)
  assertFailure(
    await send({ body: { ...INPUT, reason: 'x'.repeat(17 * 1024) } }),
    413,
    'PAYLOAD_TOO_LARGE',
  )
  assertFailure(
    await send({
      raw: gzipSync(JSON.stringify(INPUT)),
      headers: { 'Content-Encoding': 'gzip' },
    }),
    415,
    'UNSUPPORTED_MEDIA_TYPE',
  )
  assert.equal(stats.transactions, 0)
})

test('rejects invalid fields and forged body context through the real service', async (t) => {
  const { send, stats } = await fixture(t)
  for (const body of [
    {},
    [],
    { ...INPUT, actorUserId: actors.admin.userId },
    { ...INPUT, requestId: actors.admin.userId },
    { ...INPUT, roleCode: 'unknown' },
    { ...INPUT, targetUserId: 'invalid' },
    { ...INPUT, action: 'delete' },
  ]) {
    assertFailure(await send({ body }), 400, 'INVALID_ROLE_CHANGE_INPUT')
  }
  assert.equal(stats.transactions, 0)
})

for (const [code, status, publicCode] of [
  ['P3202', 403, 'FORBIDDEN'],
  ['P3203', 404, 'ROLE_TARGET_NOT_FOUND'],
  ['P3204', 404, 'ROLE_NOT_FOUND'],
  ['P3205', 409, 'ROLE_TARGET_NOT_READY'],
  ['P3206', 409, 'LAST_SYSTEM_ADMIN'],
  ['P3207', 409, 'ROLE_CHANGE_BUSY'],
]) {
  test(`database ${code} rolls back before safe HTTP ${status}/${publicCode}`, async (t) => {
    const { send, stats } = await fixture(t, {
      mutationError: Object.assign(new Error('PRIVATE_DETAIL'), { code }),
    })
    assertFailure(await send(), status, publicCode)
    assert.equal(stats.mutations.length, 1)
    assert.equal(stats.queries.at(-1).text, 'ROLLBACK')
    assert.deepEqual(stats.releases, [true])
    assert.deepEqual(stats.logs, [])
  })
}

test('unexpected database, network and timeout errors remain safe 500 responses without retry', async (t) => {
  for (const code of ['P3201', 'ECONNRESET', '57014', '55P03']) {
    const { send, stats } = await fixture(t, {
      mutationError: Object.assign(new Error('PRIVATE_DETAIL'), { code }),
    })
    assertFailure(await send(), 500, 'INTERNAL_ERROR')
    assert.equal(stats.mutations.length, 1)
    assert.equal(stats.queries.at(-1).text, 'ROLLBACK')
    assert.equal(stats.logs.length, 1)
    assert.doesNotMatch(JSON.stringify(stats.logs), /PRIVATE_DETAIL/)
  }
})

test('session and role lookup errors stop the chain and do not disclose details', async (t) => {
  for (const options of [
    { sessionError: new Error('PRIVATE_DETAIL') },
    { roleError: new Error('PRIVATE_DETAIL') },
  ]) {
    const { send, stats } = await fixture(t, options)
    assertFailure(await send(), 500, 'INTERNAL_ERROR')
    assert.equal(stats.transactions, 0)
    assert.doesNotMatch(JSON.stringify(stats.logs), /PRIVATE_DETAIL/)
  }
})

test('unsupported methods do not invoke authentication or mutation', async (t) => {
  const { send, stats } = await fixture(t)
  for (const method of ['GET', 'PUT', 'DELETE'])
    assertFailure(await send({ method }), 404, 'NOT_FOUND')
  assert.equal(stats.auth, 0)
  assert.equal(stats.transactions, 0)
})

test('requires all security and service dependencies before returning a router', async (t) => {
  const { dependencies } = await fixture(t)
  assert.throws(() => createRoleChangeRouter(), TypeError)
  for (const key of Object.keys(dependencies))
    assert.throws(
      () => createRoleChangeRouter({ ...dependencies, [key]: undefined }),
      TypeError,
    )
})
