import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { MemoryStore } from 'express-rate-limit'
import { createLoginRateLimiter } from '../src/modules/auth/login-rate-limit.middleware.js'
import { createLoginCsrfProtection } from '../src/security/login-csrf.js'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'
import { createRequireLoginCsrf } from '../src/modules/auth/login-csrf.middleware.js'
import { createRequireOrigin } from '../src/middleware/origin.middleware.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

const WEB_ORIGIN = 'http://localhost:5173'
const FIXED_TIME = Date.parse('2026-11-03T03:00:00.987Z')
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

async function startFixture(t, options = {}) {
    const stats = { credentialCalls: 0, csrfCalls: 0, logs: [], clientIp: null }
    const protection = createLoginCsrfProtection({
        secretHex: '11'.repeat(32), now: () => FIXED_TIME,
    })
    const challenge = protection.createChallenge()
    const cookies = createLoginCsrfCookie({
        httpOnly: true, secure: false, sameSite: 'lax', path: '/',
    })
    const store = options.store ?? new MemoryStore()
    const limiter = createLoginRateLimiter(options.useDefaults
        ? { store }
        : { store, limit: options.limit ?? 2, windowMs: options.windowMs ?? 60_000 })
    const requireLoginCsrf = createRequireLoginCsrf({
        loginCsrfCookie: cookies,
        loginCsrfProtection: {
            verifyChallenge(input) {
                stats.csrfCalls += 1
                return protection.verifyChallenge(input)
            },
        },
    })

    const app = express()
    // เหมือน app ปัจจุบัน: ไม่เชื่อ IP จาก proxy headers
    app.set('trust proxy', false)
    app.use(requestContext)
    app.use((request, response, next) => {
        // จำลอง IP ที่เชื่อถือได้เฉพาะใน tests ไม่อ่านจาก request headers
        if (stats.clientIp !== null) {
            Object.defineProperty(request, 'ip', { value: stats.clientIp })
        }
        next()
    })
    app.post('/login-check',
        createRequireOrigin({ webOrigin: WEB_ORIGIN }),
        limiter,
        requireLoginCsrf,
        express.json({ limit: '4kb' }),
        (request, response) => {
            // จำลองขั้นตรวจ credentials เพื่อยืนยันว่า requests ที่ถูกบล็อกมาไม่ถึง
            stats.credentialCalls += 1
            response.status(204).end()
        })
    app.use(createApiErrorHandler({
        logger: { error(...args) { stats.logs.push(args) } },
    }))

    const server = app.listen(0, '127.0.0.1')
    t.after(async () => {
        try {
            if (server.listening) {
                await new Promise((resolve, reject) => {
                    server.close((error) => error ? reject(error) : resolve())
                })
            }
        } finally {
            await store.shutdown?.()
        }
    })
    await once(server, 'listening')
    const url = `http://127.0.0.1:${server.address().port}/login-check`

    async function send({
        origin = WEB_ORIGIN,
        token = challenge.csrfToken,
        body,
        query = '',
        headers: extraHeaders = {},
    } = {}) {
        const headers = {
            Cookie: `p32_login_csrf_dev=${challenge.cookieValue}`,
            ...extraHeaders,
        }
        if (origin !== null) headers.Origin = origin
        if (token !== null) headers['X-CSRF-Token'] = token
        if (body !== undefined) headers['Content-Type'] = 'application/json'
        const response = await fetch(`${url}${query}`, {
            method: 'POST', headers, body, signal: AbortSignal.timeout(5000),
        })
        const text = await response.text()
        return { response, body: text ? JSON.parse(text) : null }
    }

    return { send, stats }
}

function assertFailure(result, status, code, message) {
    const id = result.response.headers.get('x-request-id')
    assert.equal(result.response.status, status)
    assert.match(id, UUID_PATTERN)
    assert.equal(result.response.headers.get('cache-control'), 'no-store')
    assert.equal(result.response.headers.get('set-cookie'), null)
    assert.deepEqual(result.body, { code, message, request_id: id })
}

function assertLimited(result) {
    assertFailure(result, 429, 'LOGIN_RATE_LIMITED',
        'มีคำขอเข้าสู่ระบบมากเกินไป กรุณาลองใหม่ภายหลัง')
    const retryAfter = Number(result.response.headers.get('retry-after'))
    assert.ok(Number.isInteger(retryAfter) && retryAfter > 0)
    assert.ok(result.response.headers.get('ratelimit'))
    assert.ok(result.response.headers.get('ratelimit-policy'))
    assert.equal(result.response.headers.get('x-ratelimit-limit'), null)
}

test('allows up to the limit and blocks the next request before credentials', async (t) => {
    const { send, stats } = await startFixture(t)
    for (let index = 0; index < 2; index += 1) {
        const result = await send()
        assert.equal(result.response.status, 204)
        assert.equal(result.response.headers.get('cache-control'), 'no-store')
        assert.equal(result.response.headers.get('retry-after'), null)
    }
    assertLimited(await send())
    assert.equal(stats.credentialCalls, 2)
    assert.equal(stats.csrfCalls, 2)
    assert.deepEqual(stats.logs, [])
})

test('keeps blocking repeated requests with distinct request IDs', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1 })
    assert.equal((await send()).response.status, 204)
    const first = await send()
    const second = await send()
    assertLimited(first)
    assertLimited(second)
    assert.notEqual(first.body.request_id, second.body.request_id)
    assert.equal(stats.credentialCalls, 1)
    assert.equal(stats.csrfCalls, 1)
})

test('counts failed challenges and limits them before CSRF or JSON parsing', async (t) => {
    const { send, stats } = await startFixture(t)
    for (let index = 0; index < 2; index += 1) {
        assertFailure(await send({ token: 'invalid', body: '{' }),
            403, 'CSRF_INVALID', 'ไม่สามารถยืนยันคำขอได้')
    }
    assertLimited(await send({ token: 'invalid', body: '{' }))
    assert.equal(stats.csrfCalls, 2)
    assert.equal(stats.credentialCalls, 0)
    assert.deepEqual(stats.logs, [])
})

test('rejects untrusted Origins before consuming login quota', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1 })
    for (const origin of [null, 'https://attacker.example']) {
        const result = await send({ origin })
        assertFailure(result, 403, 'ORIGIN_NOT_ALLOWED',
            'ไม่อนุญาตคำขอจากแหล่งที่มานี้')
        assert.equal(result.response.headers.get('ratelimit'), null)
    }
    assert.equal(stats.csrfCalls, 0)
    assert.equal((await send()).response.status, 204)
    assertLimited(await send())
    assert.equal(stats.credentialCalls, 1)
})

test('does not let forwarded headers change the bucket when trust proxy is false', async (t) => {
    const { send, stats } = await startFixture(t)
    // เริ่มด้วยคำขอปกติให้ library ตรวจ config ก่อน จากนั้นจำลองการปลอม headers
    assert.equal((await send()).response.status, 204)
    assert.equal((await send({ headers: {
        'X-Forwarded-For': '198.51.100.1',
        Forwarded: 'for=198.51.100.1',
    } })).response.status, 204)
    assertLimited(await send({ headers: {
        'X-Forwarded-For': '198.51.100.2',
        Forwarded: 'for=198.51.100.2',
    } }))
    assert.equal(stats.credentialCalls, 2)
})

test('changing username or query does not reset the IP request quota', async (t) => {
    const { send, stats } = await startFixture(t)
    for (const username of ['first', 'second']) {
        assert.equal((await send({
            body: JSON.stringify({ username }), query: `?username=${username}`,
        })).response.status, 204)
    }
    assertLimited(await send({ body: '{"username":"third"}', query: '?username=third' }))
    assert.equal(stats.credentialCalls, 2)
})

test('allows requests again after the real MemoryStore time window expires', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1, windowMs: 1000 })
    assert.equal((await send()).response.status, 204)
    assertLimited(await send())
    await new Promise((resolve) => setTimeout(resolve, 1200))
    assert.equal((await send()).response.status, 204)
    assert.equal(stats.credentialCalls, 2)
    assert.deepEqual(stats.logs, [])
})

test('fails closed with a safe HTTP 500 if the rate limit store fails', async (t) => {
    const store = {
        increment() { throw new Error('TEST_ONLY_PRIVATE_STORE_FAILURE') },
        decrement() {},
        resetKey() {},
    }
    const { send, stats } = await startFixture(t, { store })
    const result = await send()
    assertFailure(result, 500, 'INTERNAL_ERROR', 'เกิดข้อผิดพลาดภายในระบบ')
    assert.equal(stats.csrfCalls, 0)
    assert.equal(stats.credentialCalls, 0)
    assert.deepEqual(stats.logs, [[
        'P32 API request failed',
        { code: 'INTERNAL_ERROR', request_id: result.body.request_id },
    ]])
})

test('defaults to 60 requests in a 60-second window', async (t) => {
    const { send, stats } = await startFixture(t, { useDefaults: true })
    for (let index = 0; index < 60; index += 1) {
        assert.equal((await send()).response.status, 204)
    }
    const result = await send()
    assertLimited(result)
    assert.match(result.response.headers.get('ratelimit-policy'), /q=60; w=60/)
    assert.equal(stats.credentialCalls, 60)
})

test('groups IPv6 addresses by /56 while keeping other subnets separate', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1 })
    stats.clientIp = '2001:db8:abcd:1201::1'
    assert.equal((await send()).response.status, 204)
    stats.clientIp = '2001:db8:abcd:12ff::2'
    assertLimited(await send())
    stats.clientIp = '2001:db8:abcd:1301::1'
    assert.equal((await send()).response.status, 204)
    assert.equal(stats.credentialCalls, 2)
})

test('keeps different IPv4 addresses in separate buckets', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1 })
    stats.clientIp = '198.51.100.1'
    assert.equal((await send()).response.status, 204)
    assertLimited(await send())
    stats.clientIp = '198.51.100.2'
    assert.equal((await send()).response.status, 204)
    assert.equal(stats.credentialCalls, 2)
})

test('rejects invalid windows, limits and store dependencies before use', () => {
    for (const windowMs of [null, 0, -1, 1.5, NaN, Infinity, '1000', 2_147_483_648]) {
        assert.throws(() => createLoginRateLimiter({ windowMs }), TypeError)
    }
    for (const limit of [null, 0, -1, 1.5, NaN, Infinity, '2', Number.MAX_SAFE_INTEGER + 1]) {
        assert.throws(() => createLoginRateLimiter({ limit }), TypeError)
    }
    for (const store of [null, {}, { increment() {}, decrement() {} }]) {
        assert.throws(() => createLoginRateLimiter({ store }), TypeError)
    }
})
