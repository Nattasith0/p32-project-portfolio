import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { MemoryStore } from 'express-rate-limit'
import { createLoginAccountRateLimiter } from '../src/modules/auth/login-account-rate-limit.middleware.js'
import { createLoginRateLimiter } from '../src/modules/auth/login-rate-limit.middleware.js'
import { createLoginJsonParser, validateLoginRequest } from '../src/modules/auth/login-input.middleware.js'
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
    const stats = { credentialCalls: 0, keys: [], logs: [], clientIp: null }
    const protection = createLoginCsrfProtection({
        secretHex: '11'.repeat(32), now: () => FIXED_TIME,
    })
    const challenge = protection.createChallenge()
    const cookies = createLoginCsrfCookie({
        httpOnly: true, secure: false, sameSite: 'lax', path: '/',
    })
    const ipStore = new MemoryStore()
    const accountStore = options.store ?? new MemoryStore()
    const increment = accountStore.increment.bind(accountStore)
    accountStore.increment = (key) => {
        stats.keys.push(key)
        return increment(key)
    }
    const accountLimiter = createLoginAccountRateLimiter(options.useDefaults
        ? { store: accountStore }
        : { store: accountStore, limit: options.limit ?? 2, windowMs: options.windowMs ?? 60_000 })

    const app = express()
    app.set('trust proxy', false)
    app.use(requestContext)
    app.use((request, response, next) => {
        // จำลอง IP ที่เชื่อถือได้เฉพาะใน fixture ไม่รับจาก headers ของ client
        if (stats.clientIp !== null) Object.defineProperty(request, 'ip', { value: stats.clientIp })
        next()
    })
    app.post('/login-check',
        createRequireOrigin({ webOrigin: WEB_ORIGIN }),
        createLoginRateLimiter({ store: ipStore }),
        createRequireLoginCsrf({ loginCsrfCookie: cookies, loginCsrfProtection: protection }),
        createLoginJsonParser(),
        Object.hasOwn(options, 'context')
            ? (request, response, next) => { request.loginInput = options.context; next() }
            : validateLoginRequest,
        accountLimiter,
        (request, response) => {
            // จำลองขั้นตรวจ credentials; ไม่อ่านบัญชีหรือรหัสผ่านจากฐานข้อมูลจริง
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
            ipStore.shutdown()
            await accountStore.shutdown?.()
        }
    })
    await once(server, 'listening')
    const url = `http://127.0.0.1:${server.address().port}/login-check`

    async function send({
        username = 'student_demo', password = 'TEST_ONLY_PASSWORD',
        query = '', body = JSON.stringify({ username, password }),
    } = {}) {
        const response = await fetch(`${url}${query}`, {
            method: 'POST',
            headers: {
                Origin: WEB_ORIGIN,
                Cookie: `p32_login_csrf_dev=${challenge.cookieValue}`,
                'X-CSRF-Token': challenge.csrfToken,
                'Content-Type': 'application/json',
            },
            body,
            signal: AbortSignal.timeout(5000),
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
    assert.ok(Number(result.response.headers.get('retry-after')) > 0)
    assert.ok(result.response.headers.get('ratelimit-policy').includes('p32-login-account'))
    assert.equal(result.response.headers.get('x-ratelimit-limit'), null)
}

test('defaults to five validated requests per account per minute including successful responses', async (t) => {
    const { send, stats } = await startFixture(t, { useDefaults: true })
    for (let index = 0; index < 5; index += 1) assert.equal((await send()).response.status, 204)
    const result = await send()
    assertLimited(result)
    assert.match(result.response.headers.get('ratelimit-policy'), /"p32-login-account"; q=5; w=60/)
    assert.equal(stats.credentialCalls, 5)
    assert.deepEqual(stats.logs, [])
})

test('counts normalized username variants in the same account bucket', async (t) => {
    const { send, stats } = await startFixture(t)
    assert.equal((await send({ username: ' Student_Demo ' })).response.status, 204)
    assert.equal((await send({ username: 'STUDENT_DEMO' })).response.status, 204)
    assertLimited(await send({ username: 'student_demo' }))
    assert.equal(new Set(stats.keys).size, 1)
    assert.equal(stats.credentialCalls, 2)
})

test('changing source IP does not reset the account bucket', async (t) => {
    const { send, stats } = await startFixture(t)
    stats.clientIp = '198.51.100.1'
    assert.equal((await send()).response.status, 204)
    stats.clientIp = '198.51.100.2'
    assert.equal((await send()).response.status, 204)
    stats.clientIp = '198.51.100.3'
    assertLimited(await send())
    assert.equal(new Set(stats.keys).size, 1)
    assert.equal(stats.credentialCalls, 2)
})

test('one limited account does not consume another account quota on the same IP', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1 })
    assert.equal((await send({ username: 'first_account' })).response.status, 204)
    assertLimited(await send({ username: 'first_account' }))
    assert.equal((await send({ username: 'second_account' })).response.status, 204)
    assert.notEqual(stats.keys[0], stats.keys[2])
    assert.equal(stats.credentialCalls, 2)
})

test('changing passwords or query parameters does not reset the account quota', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1 })
    assert.equal((await send({ password: 'first', query: '?username=other' })).response.status, 204)
    assertLimited(await send({ password: 'second', query: '?username=another' }))
    assert.equal(new Set(stats.keys).size, 1)
    assert.equal(stats.credentialCalls, 1)
})

test('does not consume account quota for invalid input rejected before the limiter', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1 })
    for (const body of ['{}', '[]', '{"username":1,"password":"x"}']) {
        assertFailure(await send({ body }), 400, 'INVALID_LOGIN_INPUT', 'ข้อมูลเข้าสู่ระบบไม่ถูกต้อง')
    }
    assert.deepEqual(stats.keys, [])
    assert.equal((await send()).response.status, 204)
    assertLimited(await send())
    assert.equal(stats.credentialCalls, 1)
})

test('enforces the quota for concurrent requests to the same account', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 2 })
    const results = await Promise.all(Array.from({ length: 12 }, () => send()))
    const allowed = results.filter((result) => result.response.status === 204)
    const rejected = results.filter((result) => result.response.status !== 204)
    assert.equal(allowed.length, 2)
    assert.equal(rejected.length, 10)
    rejected.forEach(assertLimited)
    assert.equal(stats.credentialCalls, 2)
    assert.deepEqual(stats.logs, [])
})

test('allows the account again after its real MemoryStore window expires', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1, windowMs: 1000 })
    assert.equal((await send()).response.status, 204)
    assertLimited(await send())
    await new Promise((resolve) => setTimeout(resolve, 1200))
    assert.equal((await send()).response.status, 204)
    assert.equal(stats.credentialCalls, 2)
})

test('fails closed and keeps store errors out of the response and logs', async (t) => {
    const store = {
        increment() { throw new Error('TEST_ONLY_PRIVATE_STORE_FAILURE') },
        decrement() {}, resetKey() {},
    }
    const { send, stats } = await startFixture(t, { store })
    const result = await send()
    assertFailure(result, 500, 'INTERNAL_ERROR', 'เกิดข้อผิดพลาดภายในระบบ')
    assert.equal(stats.credentialCalls, 0)
    assert.deepEqual(stats.logs, [[
        'P32 API request failed',
        { code: 'INTERNAL_ERROR', request_id: result.body.request_id },
    ]])
})

test('requires validated canonical login context instead of falling back to raw input', async (t) => {
    for (const context of [
        undefined, null, {}, { username: 1 }, { username: '' },
        { username: ' Student_Demo ' }, { username: 'x'.repeat(129) },
    ]) {
        const { send, stats } = await startFixture(t, { context })
        const result = await send()
        assertFailure(result, 500, 'INTERNAL_ERROR', 'เกิดข้อผิดพลาดภายในระบบ')
        assert.deepEqual(stats.keys, [])
        assert.equal(stats.credentialCalls, 0)
    }
})

test('uses digests for store keys and treats every submitted account name uniformly', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1 })
    for (const username of ['student_demo', 'no_such_demo_account', 'นักศึกษา😀']) {
        assert.equal((await send({ username })).response.status, 204)
        const result = await send({ username })
        assertLimited(result)
        assert.equal(JSON.stringify(result.body).includes(username), false)
    }
    for (const key of stats.keys) {
        assert.match(key, /^p32-login-account:[0-9a-f]{64}$/)
        assert.equal(key.includes('TEST_ONLY_PASSWORD'), false)
        assert.equal(key.includes('student_demo'), false)
    }
    assert.equal(new Set(stats.keys).size, 3)
    assert.deepEqual(stats.logs, [])
})

test('rejects invalid rate limit policies and incompatible stores', () => {
    for (const windowMs of [null, 0, -1, 1.5, NaN, Infinity, '1000', 2_147_483_648]) {
        assert.throws(() => createLoginAccountRateLimiter({ windowMs }), TypeError)
    }
    for (const limit of [null, 0, -1, 1.5, NaN, Infinity, '5', Number.MAX_SAFE_INTEGER + 1]) {
        assert.throws(() => createLoginAccountRateLimiter({ limit }), TypeError)
    }
    for (const store of [null, {}, { increment() {}, decrement() {} }]) {
        assert.throws(() => createLoginAccountRateLimiter({ store }), TypeError)
    }
})
