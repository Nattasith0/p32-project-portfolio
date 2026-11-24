import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { readAuthConfig } from '../src/config/auth.config.js'
import { createJwtService } from '../src/security/jwt.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { createSessionAuthService } from '../src/modules/auth/session-auth.service.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createApp } from '../src/app.js'
import { createLoginCsrfProtection } from '../src/security/login-csrf.js'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'

// ข้อมูลและกุญแจสมมติสำหรับ tests เท่านั้น
const fixedTime = Date.parse('2026-11-02T03:00:00.987Z')
const issuedAt = Math.floor(fixedTime / 1000)

const session = {
    sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    expiresAt: new Date((issuedAt + 1800) * 1000),
}

const activeRow = {
    session_id: session.sessionId,
    user_id: session.userId,
    expires_at: session.expiresAt,
    username: 'student_demo',
    display_name: 'ผู้ใช้ทดสอบ',
    csrf_token_hash: 'a'.repeat(64),
}

const config = readAuthConfig({
    NODE_ENV: 'test',
    P32_JWT_SECRET_HEX: '33'.repeat(32),
    P32_CSRF_SECRET_HEX: '44'.repeat(32),
    P32_WEB_ORIGIN: 'http://localhost:5173',
})

const jwtService = createJwtService({
    secretHex: config.jwtSecretHex,
    now: () => fixedTime,
})

const sessionCookie = createSessionCookie(config.cookie)
const loginCsrfProtection = createLoginCsrfProtection({
    secretHex: config.csrfSecretHex,
    now: () => fixedTime,
})
const loginCsrfCookie = createLoginCsrfCookie(config.cookie.options)
const validToken = await jwtService.signSession(session)
const validCookie = `${config.cookie.name}=${validToken}`

const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

async function startFixture(t, {
    row = activeRow,
    repositoryError,
    readerError,
} = {}) {
    const stats = {
        lookups: [],
        logs: [],
        authCalls: 0
    }

    const sessionRepository = {
        async findActiveSession(lookup) {
            stats.lookups.push(lookup)

            if (repositoryError) {
                throw repositoryError
            }

            return row
        },

        async revokeSession() {
            assert.fail('Unexpected logout in /me tests')
        },
    }

    const sessionAuthService = createSessionAuthService({
        jwtService,
        sessionRepository,
    })

    const requireSession = createRequireSession({
        sessionCookie: readerError
            ? {
                readSessionToken() {
                    throw readerError
                },
            }
            : sessionCookie,

        sessionAuthService: {
            async authenticateSessionToken(token) {
                stats.authCalls += 1
                return sessionAuthService.authenticateSessionToken(token)
            },
        },
    })

    const app = createApp({
        userSearchService: {
            async searchUsers() {
                assert.fail('Unexpected user search in auth-only tests')
            },
        },
        roleChangeService: {
            async changeUserRole() {
                assert.fail('Unexpected role mutation in auth-only tests')
            },
        },
        authorizationService: {
            async hasAnyRole() {
                assert.fail('Unexpected role check in auth-only tests')
            },
        },
        roleService: {
            async listRoles() {
                assert.fail('Unexpected role catalog lookup in auth-only tests')
            },
        },
        webOrigin: config.webOrigin,
        requireSession,
        jwtService,
        authService: {
            async authenticateCredentials() {
                assert.fail('Unexpected credential check in session middleware tests')
            },
        },
        sessionRepository,
        sessionCookie,
        loginCsrfProtection,
        loginCsrfCookie,
        sessionService: {
            async startSession() {
                assert.fail('Unexpected session creation in session middleware tests')
            },
            async getCsrfToken() {
                assert.fail('Unexpected CSRF service call in /me tests')
            },
        },
        logger: {
            error(...args) {
                stats.logs.push(args)
            },
        },
    })

    const server = app.listen(0, '127.0.0.1')

    t.after(async () => {
        if (!server.listening) {
            return
        }

        await new Promise((resolve, reject) => {
            server.close((error) => {
                if (error) {
                    reject(error)
                } else {
                    resolve()
                }
            })
        })
    })

    await once(server, 'listening')

    const url =
        `http://127.0.0.1:${server.address().port}/api/v1/auth`

    async function get(cookieHeader, headers = {}, path = '/me') {
        const requestHeaders = { ...headers }

        if (cookieHeader !== undefined) {
            requestHeaders.Cookie = cookieHeader
        }

        const response = await fetch(`${url}${path}`, {
            headers: requestHeaders,
            signal: AbortSignal.timeout(5000),
        })

        return {
            response,
            body: await response.json(),
        }
    }

    return { get, stats }
}

function assertUnauthorized({ response, body }) {
    const requestId = response.headers.get('x-request-id')

    assert.equal(response.status, 401)
    assert.match(requestId, UUID_PATTERN)
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.equal(
        response.headers.get('www-authenticate'),
        'Session realm="P32"'
    )

    assert.deepEqual(body, {
        code: 'AUTH_REQUIRED',
        message: 'กรุณาเข้าสู่ระบบ',
        request_id: requestId,
    })
}

test('allows a valid session and returns only safe user fields', async (t) => {
    const { get, stats } = await startFixture(t)
    const { response, body } = await get(validCookie)

    assert.equal(response.status, 200)
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.match(response.headers.get('x-request-id'), UUID_PATTERN)

    assert.deepEqual(body, {
        user: {
            userId: session.userId,
            username: 'student_demo',
            displayName: 'ผู้ใช้ทดสอบ',
        },
    })

    assert.deepEqual(stats.lookups, [{
        sessionId: session.sessionId,
        userId: session.userId,
    }])

    assert.equal(stats.authCalls, 1)
    assert.deepEqual(stats.logs, [])
})

test('rejects a missing cookie without authenticating or querying', async (t) => {
    const { get, stats } = await startFixture(t)

    assertUnauthorized(await get())

    assert.equal(stats.authCalls, 0)
    assert.equal(stats.lookups.length, 0)
})

test('rejects malformed or duplicate cookies before authentication', async (t) => {
    const { get, stats } = await startFixture(t)

    for (const header of [
        'theme=dark',
        `${config.cookie.name}=`,
        `${config.cookie.name}=not-a-jwt`,
        `${validCookie}; ${validCookie}`,
    ]) {
        assertUnauthorized(await get(header))
    }

    assert.equal(stats.authCalls, 0)
    assert.equal(stats.lookups.length, 0)
})

test('uses the same rejection response for invalid JWTs and missing sessions', async (t) => {
    const otherJwtService = createJwtService({
        secretHex: '55'.repeat(32),
        now: () => fixedTime,
    })

    const wrongKeyToken = await otherJwtService.signSession(session)
    const invalidJwt = await startFixture(t)

    assertUnauthorized(await invalidJwt.get(
        `${config.cookie.name}=${wrongKeyToken}`
    ))

    assert.equal(invalidJwt.stats.authCalls, 1)
    assert.equal(invalidJwt.stats.lookups.length, 0)

    const missingSession = await startFixture(t, { row: null })

    assertUnauthorized(await missingSession.get(validCookie))

    assert.equal(missingSession.stats.authCalls, 1)
    assert.equal(missingSession.stats.lookups.length, 1)
})

test('generates fresh request IDs instead of trusting the supplied header', async (t) => {
    const { get } = await startFixture(t)
    const suppliedId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'

    const first = await get(undefined, {
        'X-Request-Id': suppliedId,
    })
    const second = await get(undefined, {
        'X-Request-Id': suppliedId,
    })

    assertUnauthorized(first)
    assertUnauthorized(second)

    assert.notEqual(first.body.request_id, suppliedId)
    assert.notEqual(second.body.request_id, suppliedId)
    assert.notEqual(first.body.request_id, second.body.request_id)
})

test('forwards unexpected failures to the error handler', async (t) => {
    for (const setting of ['readerError', 'repositoryError']) {
        const failure = new Error(`TEST_ONLY_PRIVATE_${setting}`)
        const { get, stats } = await startFixture(t, {
            [setting]: failure,
        })

        const { response, body } = await get(validCookie)
        const requestId = response.headers.get('x-request-id')

        assert.equal(response.status, 500)
        assert.equal(response.headers.get('cache-control'), 'no-store')
        assert.match(requestId, UUID_PATTERN)

        assert.deepEqual(body, {
            code: 'INTERNAL_ERROR',
            message: 'เกิดข้อผิดพลาดภายในระบบ',
            request_id: requestId,
        })

        assert.equal(JSON.stringify(body).includes(failure.message), false)
        assert.equal(JSON.stringify(body).includes(validToken), false)
        assert.deepEqual(stats.logs, [
            [
                'P32 API request failed',
                {
                    code: 'INTERNAL_ERROR',
                    request_id: requestId,
                },
            ],
        ])

        const expectedCalls = setting === 'readerError' ? 0 : 1
        assert.equal(stats.authCalls, expectedCalls)
        assert.equal(stats.lookups.length, expectedCalls)
    }
})

test('clears an existing auth context when authentication fails', async () => {
    const requireSession = createRequireSession({
        sessionCookie: {
            readSessionToken: () => null,
        },
        sessionAuthService: {
            async authenticateSessionToken() {
                assert.fail('Authentication must not run without a token')
            },
        },
    })

    const request = {
        headers: {},
        auth: { userId: 'stale-user' },
        requestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    }

    const response = {
        set() { return this },
        status() { return this },
        json() { return this },
    }

    let nextCalls = 0

    await requireSession(request, response, () => {
        nextCalls += 1
    })

    assert.equal(request.auth, null)
    assert.equal(nextCalls, 0)
})

test('rejects missing or invalid middleware dependencies', () => {
    const validCookieReader = {
        readSessionToken: () => null,
    }

    const validAuthService = {
        authenticateSessionToken: async () => null,
    }

    for (const invalid of [
        undefined, null, {}, { readSessionToken: 123 },
    ]) {
        assert.throws(() => createRequireSession({
            sessionCookie: invalid,
            sessionAuthService: validAuthService,
        }), TypeError)
    }

    for (const invalid of [
        undefined, null, {}, { authenticateSessionToken: 123 },
    ]) {
        assert.throws(() => createRequireSession({
            sessionCookie: validCookieReader,
            sessionAuthService: invalid,
        }), TypeError)
    }
})
test('public login challenge works without checking a session', async (t) => {
    const { get, stats } = await startFixture(t, {
        readerError: new Error('The session cookie reader must not run'),
        repositoryError: new Error('The session repository must not run'),
    })
    const { response, body } = await get(undefined, {}, '/login-csrf')

    assert.equal(response.status, 200)
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.match(response.headers.get('x-request-id'), UUID_PATTERN)
    assert.deepEqual(Object.keys(body), ['csrfToken'])

    const headers = response.headers.getSetCookie()
    assert.equal(headers.length, 1)
    assert.ok(headers[0].startsWith('p32_login_csrf_dev='))
    const cookieValue = loginCsrfCookie.readChallengeCookie(
        headers[0].split(';')[0]
    )
    assert.ok(cookieValue)
    assert.equal(loginCsrfProtection.verifyChallenge({
        cookieValue,
        csrfToken: body.csrfToken,
    }), true)
    assert.equal(JSON.stringify(body).includes(cookieValue), false)
    assert.equal(stats.authCalls, 0)
    assert.deepEqual(stats.lookups, [])
    assert.deepEqual(stats.logs, [])
})

test('fresh login challenges leave the existing session usable', async (t) => {
    const { get, stats } = await startFixture(t)
    const first = await get(validCookie, {}, '/login-csrf')
    const second = await get(validCookie, {}, '/login-csrf')

    for (const result of [first, second]) {
        assert.equal(result.response.status, 200)
        const headers = result.response.headers.getSetCookie()
        assert.equal(headers.length, 1)
        assert.ok(headers[0].startsWith('p32_login_csrf_dev='))
    }

    const firstCookie = loginCsrfCookie.readChallengeCookie(
        first.response.headers.getSetCookie()[0].split(';')[0]
    )
    const secondCookie = loginCsrfCookie.readChallengeCookie(
        second.response.headers.getSetCookie()[0].split(';')[0]
    )
    assert.notEqual(firstCookie, secondCookie)
    assert.notEqual(first.body.csrfToken, second.body.csrfToken)
    assert.equal(loginCsrfProtection.verifyChallenge({
        cookieValue: secondCookie,
        csrfToken: first.body.csrfToken,
    }), false)
    assert.equal(stats.authCalls, 0)
    assert.deepEqual(stats.lookups, [])

    const currentUser = await get(validCookie)
    assert.equal(currentUser.response.status, 200)
    assert.equal(currentUser.body.user.userId, session.userId)
    assert.equal(stats.authCalls, 1)
    assert.equal(stats.lookups.length, 1)
    assert.deepEqual(stats.logs, [])
})
