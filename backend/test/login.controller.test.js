import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { createLoginController } from '../src/modules/auth/login.controller.js'
import { createSessionService } from '../src/modules/auth/session.service.js'
import { createCsrfProtection } from '../src/security/csrf.js'
import { createJwtService } from '../src/security/jwt.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

const FIXED_TIME = Date.parse('2026-11-03T03:00:00.987Z')
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const safeUser = {
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    username: 'student_demo',
    displayName: 'ผู้ใช้ทดสอบ',
}
const credentials = { username: 'student_demo', password: ' TEST_ONLY_PASSWORD ' }

async function startFixture(t, options = {}) {
    const stats = {
        authCalls: [], creates: [], revokes: [], signs: [], events: [],
        cookieCalls: 0, clearCalls: 0, logs: [], rows: new Map(),
    }
    const repository = {
        async createSession(input) {
            stats.events.push('create')
            stats.creates.push(input)
            if (options.createError) throw options.createError
            const row = {
                session_id: input.sessionId, user_id: input.userId,
                csrf_token_hash: input.csrfTokenHash, expires_at: input.expiresAt,
                revoked_at: null,
            }
            stats.rows.set(row.session_id, row)
            return row
        },
        async findActiveSession() { assert.fail('Unexpected session lookup') },
        async revokeSession(context) {
            stats.events.push('revoke')
            stats.revokes.push(context)
            if (options.cleanupError) throw options.cleanupError
            const row = stats.rows.get(context.sessionId)
            assert.equal(row.user_id, context.userId)
            row.revoked_at = new Date(FIXED_TIME)
            return true
        },
    }
    const sessionService = createSessionService({
        sessionRepository: repository,
        csrfProtection: createCsrfProtection('22'.repeat(32)),
        now: () => FIXED_TIME,
    })
    const realJwt = createJwtService({ secretHex: '11'.repeat(32), now: () => FIXED_TIME })
    const secure = options.secure ?? false
    const cookieName = secure ? '__Host-p32_session' : 'p32_session_dev'
    const challengeName = secure ? '__Host-p32_login_csrf' : 'p32_login_csrf_dev'
    const cookieOptions = { httpOnly: true, secure, sameSite: 'lax', path: '/' }
    const realCookie = createSessionCookie({ name: cookieName, options: cookieOptions })
    const realChallenge = createLoginCsrfCookie(cookieOptions)
    const logger = {
        error(...args) {
            stats.logs.push(args)
            if (options.loggerError) throw options.loggerError
        },
    }
    const controller = createLoginController({
        authService: {
            async authenticateCredentials(input) {
                stats.events.push('authenticate')
                stats.authCalls.push(input)
                if (options.authError) throw options.authError
                if (options.denied) return null
                return { ...safeUser, password_hash: 'PRIVATE_HASH', roles: ['system_admin'] }
            },
        },
        sessionService,
        sessionRepository: repository,
        jwtService: {
            async signSession(session) {
                stats.events.push('sign')
                stats.signs.push(session)
                if (options.signError) throw options.signError
                return realJwt.signSession(session)
            },
        },
        sessionCookie: {
            setSessionCookie(response, value) {
                stats.events.push('set-cookie')
                stats.cookieCalls += 1
                realCookie.setSessionCookie(response, value)
                // จำลอง failure หลัง cookie header ถูกเพิ่ม แต่ยังไม่ส่ง response
                if (options.cookieError) throw options.cookieError
            },
        },
        loginCsrfCookie: {
            clearChallengeCookie(response) {
                stats.events.push('clear-challenge')
                stats.clearCalls += 1
                if (options.clearError) throw options.clearError
                realChallenge.clearChallengeCookie(response)
            },
        },
        logger,
    })

    const app = express()
    app.use(requestContext)
    app.use(express.json({ limit: 16 * 1024 }))
    // Fixture นี้จำลองผล middleware ก่อน controller ไม่ใช่ auth router จริง
    app.post('/login-check', (request, response, next) => {
        request.loginInput = Object.hasOwn(options, 'input') ? options.input : { ...credentials }
        if (options.previousCookie) response.cookie('fixture', 'preserved', { httpOnly: true })
        if (options.responseError) {
            const originalJson = response.json
            response.json = function (value) {
                if (this.statusCode === 200) throw options.responseError
                return originalJson.call(this, value)
            }
        }
        next()
    }, controller.login)
    app.use(createApiErrorHandler({ logger }))
    const server = app.listen(0, '127.0.0.1')
    t.after(async () => {
        if (server.listening) await new Promise((resolve, reject) => {
            server.close((error) => error ? reject(error) : resolve())
        })
    })
    await once(server, 'listening')
    const url = `http://127.0.0.1:${server.address().port}/login-check`

    async function post() {
        const response = await fetch(`${url}?userId=attacker&sessionId=attacker`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Cookie: `${cookieName}=client.supplied.session`,
            },
            body: JSON.stringify({ username: 'attacker', password: 'attacker', userId: 'attacker' }),
            signal: AbortSignal.timeout(5000),
        })
        return { response, body: await response.json() }
    }
    return { post, stats, realJwt, realCookie, cookieName, challengeName }
}

function assertFailure(result, status, code, message) {
    const id = result.response.headers.get('x-request-id')
    assert.equal(result.response.status, status)
    assert.match(id, UUID_PATTERN)
    assert.equal(result.response.headers.get('cache-control'), 'no-store')
    assert.deepEqual(result.body, { code, message, request_id: id })
}

function assertInternalError(result) {
    assertFailure(result, 500, 'INTERNAL_ERROR', 'เกิดข้อผิดพลาดภายในระบบ')
}

function assertCompensated(stats) {
    assert.equal(stats.creates.length, 1)
    assert.deepEqual(stats.revokes, [{
        sessionId: stats.creates[0].sessionId, userId: safeUser.userId,
    }])
    assert.ok(stats.rows.get(stats.creates[0].sessionId).revoked_at)
}

test('returns only safe user fields with a real JWT cookie and cleared challenge cookie', async (t) => {
    for (const secure of [false, true]) {
        const fixture = await startFixture(t, { secure })
        const { response, body } = await fixture.post()
        assert.equal(response.status, 200)
        assert.equal(response.headers.get('cache-control'), 'no-store')
        assert.deepEqual(body, { user: safeUser })
        const headers = response.headers.getSetCookie()
        assert.equal(headers.length, 2)
        const sessionHeader = headers.find((value) => value.startsWith(`${fixture.cookieName}=`))
        const challengeHeader = headers.find((value) => value.startsWith(`${fixture.challengeName}=;`))
        assert.ok(sessionHeader)
        assert.ok(challengeHeader)
        for (const header of headers) {
            assert.match(header, /; HttpOnly(?:;|$)/)
            assert.match(header, /; Path=\/(?:;|$)/)
            assert.match(header, /; SameSite=Lax(?:;|$)/)
            assert.doesNotMatch(header, /; Domain=/i)
            assert.equal(/; Secure(?:;|$)/.test(header), secure)
        }
        assert.equal(Date.parse(/; Expires=([^;]+)/.exec(challengeHeader)[1]), 0)
        const token = fixture.realCookie.readSessionToken(sessionHeader.split(';')[0])
        const verified = await fixture.realJwt.verifySession(token)
        assert.equal(verified.userId, safeUser.userId)
        assert.equal(verified.sessionId, fixture.stats.creates[0].sessionId)
        assert.match(verified.sessionId, UUID_PATTERN)
        assert.equal(verified.expiresAt.getTime(), (Math.floor(FIXED_TIME / 1000) + 1800) * 1000)
        assert.deepEqual(fixture.stats.authCalls, [credentials])
        assert.deepEqual(fixture.stats.events, ['authenticate', 'create', 'sign', 'clear-challenge', 'set-cookie'])
        assert.deepEqual(fixture.stats.revokes, [])
        assert.deepEqual(fixture.stats.logs, [])
    }
})

test('creates a different session for each successful login instead of reusing client input', async (t) => {
    const { post, stats } = await startFixture(t)
    assert.equal((await post()).response.status, 200)
    assert.equal((await post()).response.status, 200)
    assert.equal(stats.creates.length, 2)
    assert.notEqual(stats.creates[0].sessionId, stats.creates[1].sessionId)
    assert.notEqual(stats.creates[0].csrfTokenHash, stats.creates[1].csrfTokenHash)
    assert.deepEqual(stats.creates.map((row) => row.userId), [safeUser.userId, safeUser.userId])
})

test('rejects invalid credentials without creating a session or changing cookies', async (t) => {
    const { post, stats } = await startFixture(t, { denied: true })
    const result = await post()
    assertFailure(result, 401, 'INVALID_CREDENTIALS', 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง')
    assert.equal(result.response.headers.get('www-authenticate'), 'Session realm="P32"')
    assert.equal(result.response.headers.get('set-cookie'), null)
    assert.deepEqual(stats.events, ['authenticate'])
    assert.equal(stats.rows.size, 0)
    assert.deepEqual(stats.logs, [])
})

test('forwards credential service failures without creating sessions or cookies', async (t) => {
    const { post, stats } = await startFixture(t, { authError: new Error('PRIVATE_AUTH_FAILURE') })
    const result = await post()
    assertInternalError(result)
    assert.equal(result.response.headers.get('set-cookie'), null)
    assert.deepEqual(stats.events, ['authenticate'])
    assert.equal(stats.rows.size, 0)
})

test('does not sign or set cookies when session creation fails', async (t) => {
    const { post, stats } = await startFixture(t, { createError: new Error('PRIVATE_CREATE_FAILURE') })
    const result = await post()
    assertInternalError(result)
    assert.equal(result.response.headers.get('set-cookie'), null)
    assert.deepEqual(stats.events, ['authenticate', 'create'])
    assert.deepEqual(stats.revokes, [])
})

test('revokes the newly created session if JWT signing fails', async (t) => {
    const { post, stats } = await startFixture(t, { signError: new Error('PRIVATE_SIGN_FAILURE') })
    const result = await post()
    assertInternalError(result)
    assert.equal(result.response.headers.get('set-cookie'), null)
    assertCompensated(stats)
    assert.deepEqual(stats.events, ['authenticate', 'create', 'sign', 'revoke'])
})

test('revokes the new session if clearing the challenge cookie fails', async (t) => {
    const { post, stats } = await startFixture(t, { clearError: new Error('PRIVATE_CLEAR_FAILURE') })
    const result = await post()
    assertInternalError(result)
    assert.equal(result.response.headers.get('set-cookie'), null)
    assertCompensated(stats)
    assert.equal(stats.cookieCalls, 0)
})

test('removes buffered cookies and revokes the session after a cookie-writing failure', async (t) => {
    const { post, stats } = await startFixture(t, { cookieError: new Error('PRIVATE_COOKIE_FAILURE') })
    const result = await post()
    assertInternalError(result)
    assert.equal(result.response.headers.get('set-cookie'), null)
    assertCompensated(stats)
    assert.equal(stats.cookieCalls, 1)
    assert.equal(stats.clearCalls, 1)
})

test('also compensates if serializing the success response fails before headers are sent', async (t) => {
    const { post, stats } = await startFixture(t, { responseError: new Error('PRIVATE_RESPONSE_FAILURE') })
    const result = await post()
    assertInternalError(result)
    assert.equal(result.response.headers.get('set-cookie'), null)
    assertCompensated(stats)
})

test('preserves cookie headers that existed before login processing on failure', async (t) => {
    const { post, stats } = await startFixture(t, {
        previousCookie: true, cookieError: new Error('PRIVATE_COOKIE_FAILURE'),
    })
    const result = await post()
    assertInternalError(result)
    const headers = result.response.headers.getSetCookie()
    assert.equal(headers.length, 1)
    assert.ok(headers[0].startsWith('fixture=preserved;'))
    assertCompensated(stats)
})

test('keeps the response safe if cleanup or cleanup logging fails', async (t) => {
    for (const loggerError of [undefined, new Error('PRIVATE_LOGGER_FAILURE')]) {
        const { post, stats } = await startFixture(t, {
            signError: new Error('PRIVATE_SIGN_FAILURE'),
            cleanupError: new Error('PRIVATE_CLEANUP_FAILURE'), loggerError,
        })
        const result = await post()
        assertInternalError(result)
        assert.equal(result.response.headers.get('set-cookie'), null)
        const requestId = result.body.request_id
        assert.deepEqual(stats.logs, [
            ['P32 login session cleanup failed', { code: 'LOGIN_SESSION_CLEANUP_FAILED', request_id: requestId }],
            ['P32 API request failed', { code: 'INTERNAL_ERROR', request_id: requestId }],
        ])
        // cleanup ล้มเหลวจริง จึงไม่อ้างว่า rollback หรือเพิกถอนสำเร็จ
        assert.equal([...stats.rows.values()][0].revoked_at, null)
    }
})

test('requires validated request input before calling the credential service', async (t) => {
    for (const input of [undefined, null, {}, { username: 'student_demo', password: 123 }]) {
        const { post, stats } = await startFixture(t, { input })
        const result = await post()
        assertInternalError(result)
        assert.deepEqual(stats.authCalls, [])
        assert.equal(stats.rows.size, 0)
    }
})

test('rejects missing or invalid controller dependencies', () => {
    const dependencies = {
        authService: { authenticateCredentials() {} }, sessionService: { startSession() {} },
        jwtService: { signSession() {} }, sessionRepository: { revokeSession() {} },
        sessionCookie: { setSessionCookie() {} }, loginCsrfCookie: { clearChallengeCookie() {} },
        logger: { error() {} },
    }
    for (const name of Object.keys(dependencies)) {
        for (const value of [null, {}, 123]) {
            assert.throws(() => createLoginController({ ...dependencies, [name]: value }), TypeError)
        }
    }
})
