import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request as httpRequest } from 'node:http'
import express from 'express'
import { createLoginCsrfProtection } from '../src/security/login-csrf.js'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'
import { createRequireLoginCsrf } from '../src/modules/auth/login-csrf.middleware.js'
import { createRequireOrigin } from '../src/middleware/origin.middleware.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

// กุญแจและเวลาเป็นค่าทดสอบ ไม่อ่าน .env และไม่เชื่อมฐานข้อมูล
const SECRET = '11'.repeat(32)
const FIXED_TIME = Date.parse('2026-11-03T03:00:00.987Z')
const WEB_ORIGIN = 'http://localhost:5173'
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const issuer = createLoginCsrfProtection({
    secretHex: SECRET,
    now: () => FIXED_TIME,
})

async function startFixture(t, options = {}) {
    const challenge = issuer.createChallenge()
    const stats = {
        cookieReads: 0,
        verifications: 0,
        handled: 0,
        logs: [],
        now: FIXED_TIME,
    }
    const realCookies = createLoginCsrfCookie({
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
    })
    const realProtection = createLoginCsrfProtection({
        secretHex: SECRET,
        now: () => stats.now,
    })
    const requireLoginCsrf = createRequireLoginCsrf({
        loginCsrfCookie: {
            readChallengeCookie(header) {
                stats.cookieReads += 1
                if (options.cookieError) throw options.cookieError
                return realCookies.readChallengeCookie(header)
            },
        },
        loginCsrfProtection: {
            verifyChallenge(input) {
                stats.verifications += 1
                if (options.verificationError) throw options.verificationError
                if (Object.hasOwn(options, 'verificationValue')) {
                    return options.verificationValue
                }
                return realProtection.verifyChallenge(input)
            },
        },
    })

    const app = express()
    app.use(requestContext)
    app.use(createRequireOrigin({ webOrigin: WEB_ORIGIN }))
    // เส้นทางจำลองสำหรับ tests เท่านั้น ยังไม่ใช่ POST /auth/login จริง
    app.post('/login-check', requireLoginCsrf, express.json({ limit: '4kb' }),
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
    const url = `http://127.0.0.1:${server.address().port}/login-check`
    const validCookie = `p32_login_csrf_dev=${challenge.cookieValue}`

    function send({
        origin = WEB_ORIGIN,
        cookie = validCookie,
        token = challenge.csrfToken,
        query = '',
        body,
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
            const request = httpRequest(`${url}${query}`, {
                method: 'POST', headers, agent: false, timeout: 5000,
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

    return { send, stats, challenge, validCookie }
}

function assertFailure(result, status, code, message) {
    const requestId = result.headers['x-request-id']
    assert.equal(result.status, status)
    assert.match(requestId, UUID_PATTERN)
    assert.equal(result.headers['cache-control'], 'no-store')
    assert.equal(result.headers['set-cookie'], undefined)
    assert.equal(result.headers['www-authenticate'], undefined)
    assert.deepEqual(result.body, { code, message, request_id: requestId })
}

function assertCsrfRejected(result) {
    assertFailure(result, 403, 'CSRF_INVALID', 'ไม่สามารถยืนยันคำขอได้')
}

test('allows a valid login challenge without an authenticated session', async (t) => {
    const { send, stats } = await startFixture(t)
    const result = await send()
    assert.equal(result.status, 204)
    assert.equal(result.body, null)
    assert.equal(result.headers['cache-control'], 'no-store')
    assert.equal(result.headers['set-cookie'], undefined)
    assert.match(result.headers['x-request-id'], UUID_PATTERN)
    assert.equal(stats.handled, 1)
    assert.equal(stats.cookieReads, 1)
    assert.equal(stats.verifications, 1)
    assert.deepEqual(stats.logs, [])
})

test('rejects missing, malformed, oversized and duplicate token headers', async (t) => {
    const { send, stats, challenge } = await startFixture(t)
    for (const token of [
        null, '', 'invalid', 'a'.repeat(65),
        challenge.csrfToken + '=',
        [challenge.csrfToken, challenge.csrfToken],
    ]) {
        assertCsrfRejected(await send({ token }))
    }
    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('rejects missing, malformed, oversized and duplicate challenge cookies', async (t) => {
    const { send, stats, validCookie } = await startFixture(t)
    for (const cookie of [
        null, '', 'p32_session_dev=test.payload.signature',
        'p32_login_csrf_dev=invalid',
        `${validCookie}; ${validCookie}`,
        `${validCookie}; other=${'x'.repeat(8192)}`,
    ]) {
        assertCsrfRejected(await send({ cookie }))
    }
    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('rejects tokens from another challenge or key and altered signatures', async (t) => {
    const { send, stats, challenge } = await startFixture(t)
    const otherChallenge = issuer.createChallenge()
    const otherKey = createLoginCsrfProtection({
        secretHex: '22'.repeat(32), now: () => FIXED_TIME,
    }).createChallenge()
    const [expiration, signature] = challenge.csrfToken.split('.')
    const altered = `${expiration}.${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`
    for (const token of [otherChallenge.csrfToken, otherKey.csrfToken, altered]) {
        assertCsrfRejected(await send({ token }))
    }
    // ใช้ nonce ของกุญแจอื่นคู่กับ token ของมัน ก็ยังต้องถูกปฏิเสธ
    assertCsrfRejected(await send({
        cookie: `p32_login_csrf_dev=${otherKey.cookieValue}`,
        token: otherKey.csrfToken,
    }))
    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('allows before expiry and rejects at and after expiry', async (t) => {
    const { send, stats, challenge } = await startFixture(t)
    const expiration = challenge.expiresAt.getTime()
    stats.now = expiration - 1
    assert.equal((await send()).status, 204)
    stats.now = expiration
    assertCsrfRejected(await send())
    stats.now = expiration + 1000
    assertCsrfRejected(await send())
    assert.equal(stats.handled, 1)
    assert.deepEqual(stats.logs, [])
})

test('does not accept tokens or nonce values supplied only in query or body', async (t) => {
    const { send, stats, challenge } = await startFixture(t)
    const query = `?csrfToken=${challenge.csrfToken}&cookieValue=${challenge.cookieValue}`
    const body = JSON.stringify(challenge)
    assertCsrfRejected(await send({ token: null, query, body }))
    assertCsrfRejected(await send({ cookie: null, query, body }))
    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('rejects untrusted or duplicate Origins before reading cookies or verifying', async (t) => {
    const { send, stats } = await startFixture(t)
    for (const origin of [null, 'https://attacker.example', [WEB_ORIGIN, WEB_ORIGIN]]) {
        assertFailure(await send({ origin, body: '{' }),
            403, 'ORIGIN_NOT_ALLOWED', 'ไม่อนุญาตคำขอจากแหล่งที่มานี้')
    }
    assert.equal(stats.cookieReads, 0)
    assert.equal(stats.verifications, 0)
    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('rejects invalid challenges before parsing JSON or reaching the next handler', async (t) => {
    const { send, stats } = await startFixture(t)
    assertCsrfRejected(await send({ token: null, body: '{' }))
    assertFailure(await send({ body: '{' }),
        400, 'INVALID_JSON', 'รูปแบบ JSON ไม่ถูกต้อง')
    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('forwards cookie or verification failures as safe HTTP 500 responses', async (t) => {
    for (const setting of ['cookieError', 'verificationError']) {
        const failure = new Error(`TEST_ONLY_PRIVATE_${setting}`)
        const { send, stats, challenge } = await startFixture(t, { [setting]: failure })
        const result = await send()
        assertFailure(result, 500, 'INTERNAL_ERROR', 'เกิดข้อผิดพลาดภายในระบบ')
        assert.equal(stats.handled, 0)
        assert.deepEqual(stats.logs, [[
            'P32 API request failed',
            { code: 'INTERNAL_ERROR', request_id: result.body.request_id },
        ]])
        const publicOutput = JSON.stringify({ body: result.body, logs: stats.logs })
        assert.equal(publicOutput.includes(failure.message), false)
        assert.equal(publicOutput.includes(challenge.csrfToken), false)
        assert.equal(publicOutput.includes(challenge.cookieValue), false)
        assert.equal(stats.verifications, setting === 'cookieError' ? 0 : 1)
    }
})

test('does not accept truthy values in place of a true verification result', async (t) => {
    for (const verificationValue of [undefined, null, false, 1, 'true', {}]) {
        const { send, stats } = await startFixture(t, { verificationValue })
        assertCsrfRejected(await send())
        assert.equal(stats.handled, 0)
    }
})

test('rejects missing or invalid middleware dependencies', () => {
    for (const invalid of [undefined, null, {}, { readChallengeCookie: 1 }]) {
        assert.throws(() => createRequireLoginCsrf({
            loginCsrfCookie: invalid,
            loginCsrfProtection: { verifyChallenge: () => true },
        }), TypeError)
    }
    for (const invalid of [undefined, null, {}, { verifyChallenge: 1 }]) {
        assert.throws(() => createRequireLoginCsrf({
            loginCsrfCookie: { readChallengeCookie: () => null },
            loginCsrfProtection: invalid,
        }), TypeError)
    }
})
