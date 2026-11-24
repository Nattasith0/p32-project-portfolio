import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { createCsrfController } from '../src/modules/auth/csrf.controller.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

// ข้อมูลสมมติ: ไม่ใช่ JWT หรือ CSRF token สำหรับใช้งานจริง
const TEST_TOKEN = 'test.payload.signature'
const TEST_COOKIE = `p32_session_dev=${TEST_TOKEN}`
const TEST_CSRF_TOKEN = 'c'.repeat(43)
const identity = {
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    username: 'student_demo',
    displayName: 'ผู้ใช้ทดสอบ',
}
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

async function startFixture(t, {
    authenticatedIdentity = identity,
    csrfToken = TEST_CSRF_TOKEN,
    serviceError,
} = {}) {
    const stats = { csrfCalls: [], authCalls: 0, logs: [] }
    const sessionCookie = createSessionCookie({
        name: 'p32_session_dev',
        options: {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            path: '/',
        },
    })

    const requireSession = createRequireSession({
        sessionCookie,
        // จำลองผล authentication; การตรวจ JWT จริงมี tests แยกแล้ว
        sessionAuthService: {
            async authenticateSessionToken(token) {
                stats.authCalls += 1
                return token === TEST_TOKEN ? authenticatedIdentity : null
            },
        },
    })

    const controller = createCsrfController({
        sessionService: {
            async getCsrfToken(context) {
                stats.csrfCalls.push(context)
                if (serviceError) throw serviceError
                return csrfToken
            },
        },
    })

    const app = express()
    app.use(requestContext)
    app.get('/api/v1/auth/csrf', requireSession, controller.getCsrfToken)
    app.use(createApiErrorHandler({
        logger: {
            error(...args) {
                stats.logs.push(args)
            },
        },
    }))

    const server = app.listen(0, '127.0.0.1')
    t.after(async () => {
        if (!server.listening) return
        await new Promise((resolve, reject) => {
            server.close((error) => {
                if (error) reject(error)
                else resolve()
            })
        })
    })
    await once(server, 'listening')

    const url =
        `http://127.0.0.1:${server.address().port}/api/v1/auth/csrf`

    async function get({ cookie = TEST_COOKIE, query = '' } = {}) {
        const response = await fetch(`${url}${query}`, {
            headers: cookie === null ? {} : { Cookie: cookie },
            signal: AbortSignal.timeout(5000),
        })
        return { response, body: await response.json() }
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
        'Session realm="P32"',
    )
    assert.deepEqual(body, {
        code: 'AUTH_REQUIRED',
        message: 'กรุณาเข้าสู่ระบบ',
        request_id: requestId,
    })
}

test('returns only the CSRF token and uses authenticated IDs instead of query parameters', async (t) => {
    const { get, stats } = await startFixture(t)
    const { response, body } = await get({
        query: '?userId=attacker-user&sessionId=attacker-session',
    })

    assert.equal(response.status, 200)
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.match(response.headers.get('content-type'), /^application\/json\b/)
    assert.match(response.headers.get('x-request-id'), UUID_PATTERN)
    assert.deepEqual(body, { csrfToken: TEST_CSRF_TOKEN })
    assert.deepEqual(stats.csrfCalls, [{
        sessionId: identity.sessionId,
        userId: identity.userId,
    }])
    assert.equal(stats.authCalls, 1)
    assert.deepEqual(stats.logs, [])
})

test('rejects a missing session cookie without calling authentication or the CSRF service', async (t) => {
    const { get, stats } = await startFixture(t)

    assertUnauthorized(await get({ cookie: null }))
    assert.equal(stats.authCalls, 0)
    assert.deepEqual(stats.csrfCalls, [])
    assert.deepEqual(stats.logs, [])
})

test('does not call the CSRF service when session authentication rejects the request', async (t) => {
    const { get, stats } = await startFixture(t, {
        authenticatedIdentity: null,
    })

    assertUnauthorized(await get())
    assert.equal(stats.authCalls, 1)
    assert.deepEqual(stats.csrfCalls, [])
    assert.deepEqual(stats.logs, [])
})

test('requires login again when the service cannot return a CSRF token', async (t) => {
    const { get, stats } = await startFixture(t, { csrfToken: null })

    assertUnauthorized(await get())
    assert.deepEqual(stats.csrfCalls, [{
        sessionId: identity.sessionId,
        userId: identity.userId,
    }])
    assert.deepEqual(stats.logs, [])
})

test('forwards service failures as a safe HTTP 500 without exposing private details', async (t) => {
    const failure = new Error('TEST_ONLY_PRIVATE_DATABASE_DETAIL')
    const { get, stats } = await startFixture(t, { serviceError: failure })
    const { response, body } = await get()
    const requestId = response.headers.get('x-request-id')

    assert.equal(response.status, 500)
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.match(requestId, UUID_PATTERN)
    assert.deepEqual(body, {
        code: 'INTERNAL_ERROR',
        message: 'เกิดข้อผิดพลาดภายในระบบ',
        request_id: requestId,
    })
    assert.deepEqual(stats.logs, [[
        'P32 API request failed',
        { code: 'INTERNAL_ERROR', request_id: requestId },
    ]])
    assert.equal(stats.csrfCalls.length, 1)
})

test('rejects a session service without a getCsrfToken function', () => {
    for (const sessionService of [
        undefined, null, {}, { getCsrfToken: 123 },
    ]) {
        assert.throws(
            () => createCsrfController({ sessionService }),
            TypeError,
        )
    }
})
