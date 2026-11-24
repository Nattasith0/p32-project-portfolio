import test from 'node:test'
import assert from 'node:assert/strict'
import { createJwtService } from '../src/security/jwt.js'
import { createSessionAuthService } from '../src/modules/auth/session-auth.service.js'

// ข้อมูลและกุญแจสมมติสำหรับ tests เท่านั้น
const fixedTime = Date.parse('2026-11-02T03:00:00.987Z')
const issuedAt = Math.floor(fixedTime / 1000)

const session = {
    sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    expiresAt: new Date((issuedAt + 1800) * 1000),
}

const realJwtService = createJwtService({
    secretHex: '33'.repeat(32),
    now: () => fixedTime,
})

const validToken = await realJwtService.signSession(session)

const activeRow = {
    session_id: session.sessionId,
    user_id: session.userId,
    expires_at: session.expiresAt,
    username: 'student_demo',
    display_name: 'ผู้ใช้ทดสอบ',
    csrf_token_hash: 'a'.repeat(64),
}

function createFixture({
    row = activeRow,
    repositoryError,
    jwtService = realJwtService,
} = {}) {
    const lookups = []

    const sessionRepository = {
        async findActiveSession(lookup) {
            lookups.push(lookup)

            if (repositoryError) {
                throw repositoryError
            }

            return row
        },
    }

    const service = createSessionAuthService({
        jwtService,
        sessionRepository,
    })

    return { service, lookups }
}

test('authenticates a matching session and returns only allowed fields', async () => {
    const { service, lookups } = createFixture()

    const result = await service.authenticateSessionToken(validToken)

    assert.deepEqual(lookups, [{
        sessionId: session.sessionId,
        userId: session.userId,
    }])

    assert.deepEqual(result, {
        userId: session.userId,
        username: 'student_demo',
        displayName: 'ผู้ใช้ทดสอบ',
        sessionId: session.sessionId,
        expiresAt: session.expiresAt,
    })
})

test('rejects invalid JWTs without querying the repository', async () => {
    const otherJwtService = createJwtService({
        secretHex: '44'.repeat(32),
        now: () => fixedTime,
    })

    const wrongKeyToken = await otherJwtService.signSession(session)
    const { service, lookups } = createFixture()

    for (const token of [undefined, null, 'not-a-jwt', wrongKeyToken]) {
        assert.equal(
            await service.authenticateSessionToken(token),
            null
        )
    }

    assert.equal(lookups.length, 0)
})

test('rejects when the repository finds no active session', async () => {
    const { service, lookups } = createFixture({ row: null })

    assert.equal(
        await service.authenticateSessionToken(validToken),
        null
    )
    assert.equal(lookups.length, 1)
})

test('rejects a mismatched session, owner or expiration', async () => {
    const invalidRows = [
        {
            ...activeRow,
            session_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        },
        {
            ...activeRow,
            user_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
        },
        {
            ...activeRow,
            expires_at: new Date(session.expiresAt.getTime() + 1000),
        },
    ]

    for (const row of invalidRows) {
        const { service, lookups } = createFixture({ row })

        assert.equal(
            await service.authenticateSessionToken(validToken),
            null
        )
        assert.equal(lookups.length, 1)
    }
})

test('rejects an expired JWT without querying the repository', async () => {
    const expiredJwtService = createJwtService({
        secretHex: '33'.repeat(32),
        now: () => session.expiresAt.getTime(),
    })

    const { service, lookups } = createFixture({
        jwtService: expiredJwtService,
    })

    assert.equal(
        await service.authenticateSessionToken(validToken),
        null
    )
    assert.equal(lookups.length, 0)
})

test('propagates repository errors instead of authenticating', async () => {
    const databaseError = new Error('Simulated database failure')

    const { service, lookups } = createFixture({
        repositoryError: databaseError,
    })

    await assert.rejects(
        service.authenticateSessionToken(validToken),
        (error) => error === databaseError
    )

    assert.equal(lookups.length, 1)
})

test('propagates JWT service errors without querying the repository', async () => {
    const verificationError = new Error('Simulated JWT service failure')

    const { service, lookups } = createFixture({
        jwtService: {
            async verifySession() {
                throw verificationError
            },
        },
    })

    await assert.rejects(
        service.authenticateSessionToken(validToken),
        (error) => error === verificationError
    )

    assert.equal(lookups.length, 0)
})

test('rejects missing or invalid service dependencies', () => {
    const validRepository = {
        findActiveSession: async () => null,
    }

    for (const invalid of [
        undefined, null, {}, { verifySession: 123 },
    ]) {
        assert.throws(() => createSessionAuthService({
            jwtService: invalid,
            sessionRepository: validRepository,
        }), {
            name: 'TypeError',
            message: 'A JWT service is required',
        })
    }

    for (const invalid of [
        undefined, null, {}, { findActiveSession: 123 },
    ]) {
        assert.throws(() => createSessionAuthService({
            jwtService: realJwtService,
            sessionRepository: invalid,
        }), {
            name: 'TypeError',
            message: 'A session repository is required',
        })
    }
})