import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request as httpRequest } from 'node:http'
import express from 'express'
import { createCsrfProtection } from '../src/security/csrf.js'
import { createSessionService } from '../src/modules/auth/session.service.js'
import { createRequireCsrf } from '../src/modules/auth/csrf.middleware.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { createRequireOrigin } from '../src/middleware/origin.middleware.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

// ค่าทั้งหมดเป็นข้อมูลสมมติสำหรับ tests เท่านั้น
const WEB_ORIGIN = 'http://localhost:5173'
const TEST_JWT = 'test.payload.signature'
const TEST_COOKIE = `p32_session_dev=${TEST_JWT}`
const identity = {
    sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
}
const protection = createCsrfProtection('55'.repeat(32))
const validToken = protection.createToken(identity)
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

async function startFixture(t, options = {}) {
    const stats = { authCalls: 0, serviceCalls: [], lookups: [], handled: 0, logs: [] }
    const repository = {
        async createSession() {
            assert.fail('These tests must not create sessions')
        },
        async findActiveSession(context) {
            stats.lookups.push(context)
            if (options.active === false) return null

            return {
                session_id: identity.sessionId,
                user_id: identity.userId,
                csrf_token_hash: protection.hashToken(validToken),
            }
        },
    }
    const realSessionService = createSessionService({
        sessionRepository: repository,
        csrfProtection: protection,
    })
    const sessionService = {
        async getCsrfToken(context) {
            stats.serviceCalls.push(context)
            if (options.serviceError) throw options.serviceError
            if (Object.hasOwn(options, 'serviceValue')) return options.serviceValue
            return realSessionService.getCsrfToken(context)
        },
    }
    const sessionCookie = createSessionCookie({
        name: 'p32_session_dev',
        options: { httpOnly: true, secure: false, sameSite: 'lax', path: '/' },
    })
    const requireSession = createRequireSession({
        sessionCookie,
        // จำลองผลตรวจ JWT; tests นี้เน้น Origin/session/CSRF middleware ร่วมกัน
        sessionAuthService: {
            async authenticateSessionToken(token) {
                stats.authCalls += 1
                return token === TEST_JWT ? identity : null
            },
        },
    })

    const app = express()
    app.use(requestContext)
    app.use(createRequireOrigin({ webOrigin: WEB_ORIGIN }))
    app.all('/change', requireSession, createRequireCsrf({ sessionService }),
        (request, response) => {
            stats.handled += 1
            response.status(204).end()
        })
    app.use(createApiErrorHandler({
        logger: { error(...args) { stats.logs.push(args) } },
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
    const baseUrl = `http://127.0.0.1:${server.address().port}/change`

    function send({
        method = 'POST', origin = WEB_ORIGIN, cookie = TEST_COOKIE,
        token = validToken, query = '', body,
    } = {}) {
        const headers = {}
        if (origin !== null) headers.Origin = origin
        if (cookie !== null) headers.Cookie = cookie
        if (token !== null) headers['X-CSRF-Token'] = token
        if (body !== undefined) {
            headers['Content-Type'] = 'application/json'
            headers['Content-Length'] = Buffer.byteLength(body)
        }

        return new Promise((resolve, reject) => {
            const request = httpRequest(`${baseUrl}${query}`, {
                method, headers, agent: false, timeout: 5000,
            }, (response) => {
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
            })
            request.on('error', reject)
            request.on('timeout', () => request.destroy(new Error('Test request timed out')))
            request.end(body)
        })
    }

    return { send, stats }
}

function assertFailure(result, status, code, message) {
    const requestId = result.headers['x-request-id']
    assert.equal(result.status, status)
    assert.match(requestId, UUID_PATTERN)
    assert.equal(result.headers['cache-control'], 'no-store')
    assert.deepEqual(result.body, { code, message, request_id: requestId })
}

function assertCsrfRejected(result) {
    assertFailure(result, 403, 'CSRF_INVALID', 'ไม่สามารถยืนยันคำขอได้')
}

function assertUnauthorized(result) {
    assertFailure(result, 401, 'AUTH_REQUIRED', 'กรุณาเข้าสู่ระบบ')
    assert.equal(result.headers['www-authenticate'], 'Session realm="P32"')
}

function assertSafeInternalError(result, stats) {
    assertFailure(result, 500, 'INTERNAL_ERROR', 'เกิดข้อผิดพลาดภายในระบบ')
    assert.deepEqual(stats.logs, [[
        'P32 API request failed',
        { code: 'INTERNAL_ERROR', request_id: result.body.request_id },
    ]])
    assert.equal(stats.handled, 0)
}

test('allows state-changing requests with a token bound to the authenticated session', async (t) => {
    const { send, stats } = await startFixture(t)

    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        const result = await send({ method, query: '?userId=attacker&sessionId=attacker' })
        assert.equal(result.status, 204)
        assert.equal(result.headers['cache-control'], 'no-store')
    }

    assert.equal(stats.handled, 4)
    assert.deepEqual(stats.serviceCalls, Array.from({ length: 4 }, () => ({ ...identity })))
    assert.deepEqual(stats.lookups, stats.serviceCalls)
    assert.deepEqual(stats.logs, [])
})

test('rejects missing, malformed and duplicate tokens before calling the session service', async (t) => {
    const { send, stats } = await startFixture(t)

    for (const token of [
        null, '', 'a'.repeat(42), 'a'.repeat(44),
        `${'a'.repeat(42)}!`, `${'a'.repeat(42)}=`,
        [validToken, validToken],
    ]) {
        assertCsrfRejected(await send({ token }))
    }

    // token ที่อยู่ใน query/body ไม่ทดแทน header ที่กำหนด
    assertCsrfRejected(await send({
        token: null,
        query: `?csrfToken=${validToken}`,
        body: JSON.stringify({ csrfToken: validToken }),
    }))
    assert.deepEqual(stats.serviceCalls, [])
    assert.deepEqual(stats.lookups, [])
    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('rejects validly shaped tokens from another session, account or server key', async (t) => {
    const { send, stats } = await startFixture(t)
    const otherTokens = [
        protection.createToken({ ...identity, sessionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' }),
        protection.createToken({ ...identity, userId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' }),
        createCsrfProtection('66'.repeat(32)).createToken(identity),
    ]

    for (const token of otherTokens) assertCsrfRejected(await send({ token }))
    assert.equal(stats.lookups.length, 3)
    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('rejects untrusted Origins before authentication and CSRF checks', async (t) => {
    const { send, stats } = await startFixture(t)

    for (const origin of [null, 'https://attacker.example']) {
        assertFailure(await send({ origin }), 403, 'ORIGIN_NOT_ALLOWED',
            'ไม่อนุญาตคำขอจากแหล่งที่มานี้')
    }
    assert.equal(stats.authCalls, 0)
    assert.deepEqual(stats.serviceCalls, [])
    assert.equal(stats.handled, 0)
})

test('requires an authenticated session even when the CSRF token is correct', async (t) => {
    const { send, stats } = await startFixture(t)
    assertUnauthorized(await send({ cookie: null }))
    assert.deepEqual(stats.serviceCalls, [])
    assert.deepEqual(stats.lookups, [])
    assert.equal(stats.handled, 0)
})

test('requires login again if the active session disappears before CSRF verification', async (t) => {
    const { send, stats } = await startFixture(t, { active: false })
    assertUnauthorized(await send())
    assert.equal(stats.lookups.length, 1)
    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('fails safely when the session service returns a value outside its contract', async (t) => {
    for (const serviceValue of [undefined, false, '', {}, `${validToken}\n`]) {
        const { send, stats } = await startFixture(t, { serviceValue })
        assertSafeInternalError(await send(), stats)
    }
})

test('forwards session service errors without exposing tokens or private details', async (t) => {
    const { send, stats } = await startFixture(t, {
        serviceError: new Error(`TEST_ONLY_PRIVATE_DETAIL_${validToken}`),
    })
    assertSafeInternalError(await send(), stats)
})

test('rejects a missing or invalid session service at construction', () => {
    for (const sessionService of [undefined, null, {}, { getCsrfToken: 123 }]) {
        assert.throws(() => createRequireCsrf({ sessionService }), TypeError)
    }
})

test('rejects non-string values and trailing line breaks before reading session data', async () => {
    let serviceCalls = 0
    const requireCsrf = createRequireCsrf({
        sessionService: {
            async getCsrfToken() {
                serviceCalls += 1
                assert.fail('Invalid header values must not reach the service')
            },
        },
    })

    // ค่าบางชนิดส่งผ่าน HTTP ไม่ได้ จึงทดสอบตรงที่ขอบเขต middleware
    for (const value of [undefined, null, 123, [validToken], Buffer.from(validToken),
        `${validToken}\n`, `${validToken}\r\n`, 'ก'.repeat(43)]) {
        let status
        // จำลอง header ที่ requestContext ตั้งไว้ก่อนเข้า middleware นี้
        const headers = new Map([
            ['x-request-id', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'],
        ])
        let body
        await requireCsrf({
            headers: { 'x-csrf-token': value },
            requestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
        }, {
            set(name, value) { headers.set(name.toLowerCase(), value); return this },
            status(value) { status = value; return this },
            json(value) { body = value; return this },
        }, () => assert.fail('Rejected requests must not continue'))

        assertCsrfRejected({ status, headers: Object.fromEntries(headers), body })
    }
    assert.equal(serviceCalls, 0)
})
