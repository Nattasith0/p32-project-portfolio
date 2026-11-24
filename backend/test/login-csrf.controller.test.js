import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { createLoginCsrfProtection } from '../src/security/login-csrf.js'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'
import { createLoginCsrfController } from '../src/modules/auth/login-csrf.controller.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

// กุญแจและเวลาเป็นค่าทดสอบ ไม่ใช่ค่าจาก .env
const FIXED_TIME = Date.parse('2026-11-03T03:00:00.987Z')
const EXPIRES_MS = (Math.floor(FIXED_TIME / 1000) + 600) * 1000
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

async function startFixture(t, {
    secure = false,
    challengeError,
    cookieError,
} = {}) {
    const stats = { challenges: [], cookieCalls: 0, logs: [] }
    const protection = createLoginCsrfProtection({
        secretHex: '11'.repeat(32),
        now: () => FIXED_TIME,
    })
    const cookies = createLoginCsrfCookie({
        httpOnly: true,
        secure,
        sameSite: 'lax',
        path: '/',
    })
    const controller = createLoginCsrfController({
        loginCsrfProtection: {
            createChallenge() {
                if (challengeError) throw challengeError
                const challenge = protection.createChallenge()
                stats.challenges.push(challenge)
                return challenge
            },
        },
        loginCsrfCookie: {
            setChallengeCookie(response, challenge) {
                stats.cookieCalls += 1
                if (cookieError) throw cookieError
                return cookies.setChallengeCookie(response, challenge)
            },
        },
    })

    const app = express()
    app.use(requestContext)
    // Public fixture: controller ต้องทำงานได้โดยไม่มี request.auth
    app.get('/api/v1/auth/login-csrf', controller.getLoginCsrf)
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
        `http://127.0.0.1:${server.address().port}/api/v1/auth/login-csrf`

    async function get({ query = '', cookie } = {}) {
        const response = await fetch(`${url}${query}`, {
            headers: cookie === undefined ? {} : { Cookie: cookie },
            signal: AbortSignal.timeout(5000),
        })
        return { response, body: await response.json() }
    }

    return { get, stats, protection }
}

function assertChallenge(result, protection, secure = false) {
    const { response, body } = result
    const name = secure ? '__Host-p32_login_csrf' : 'p32_login_csrf_dev'
    assert.equal(response.status, 200)
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.match(response.headers.get('x-request-id'), UUID_PATTERN)
    assert.match(response.headers.get('content-type'), /^application\/json\b/)
    assert.deepEqual(Object.keys(body), ['csrfToken'])

    const setCookies = response.headers.getSetCookie()
    assert.equal(setCookies.length, 1)
    const [pair, ...parts] = setCookies[0].split(';').map((part) => part.trim())
    assert.ok(pair.startsWith(`${name}=`))
    const cookieValue = pair.slice(name.length + 1)
    assert.equal(cookieValue.length, 43)

    const attributes = new Map(parts.map((part) => {
        const index = part.indexOf('=')
        return index === -1
            ? [part.toLowerCase(), true]
            : [part.slice(0, index).toLowerCase(), part.slice(index + 1)]
    }))
    assert.equal(attributes.get('httponly'), true)
    assert.equal(attributes.get('path'), '/')
    assert.equal(attributes.get('samesite'), 'Lax')
    assert.equal(attributes.has('secure'), secure)
    assert.equal(attributes.has('domain'), false)
    assert.equal(Date.parse(attributes.get('expires')), EXPIRES_MS)
    assert.equal(protection.verifyChallenge({ cookieValue, csrfToken: body.csrfToken }), true)

    return { cookieValue, csrfToken: body.csrfToken }
}

function assertSafeError({ response, body }, stats) {
    const requestId = response.headers.get('x-request-id')
    assert.equal(response.status, 500)
    assert.match(requestId, UUID_PATTERN)
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.equal(response.headers.get('set-cookie'), null)
    assert.deepEqual(body, {
        code: 'INTERNAL_ERROR',
        message: 'เกิดข้อผิดพลาดภายในระบบ',
        request_id: requestId,
    })
    assert.deepEqual(stats.logs, [[
        'P32 API request failed',
        { code: 'INTERNAL_ERROR', request_id: requestId },
    ]])
}

test('issues a public challenge as an HttpOnly cookie and a matching JSON token', async (t) => {
    for (const secure of [false, true]) {
        const { get, stats, protection } = await startFixture(t, { secure })
        const pair = assertChallenge(await get(), protection, secure)
        assert.equal(pair.cookieValue, stats.challenges[0].cookieValue)
        assert.equal(pair.csrfToken, stats.challenges[0].csrfToken)
        assert.equal(stats.cookieCalls, 1)
        assert.deepEqual(stats.logs, [])
    }
})

test('issues fresh independent cookie-token pairs on successive requests', async (t) => {
    const { get, stats, protection } = await startFixture(t)
    const first = assertChallenge(await get(), protection)
    const second = assertChallenge(await get(), protection)

    assert.notEqual(first.cookieValue, second.cookieValue)
    assert.notEqual(first.csrfToken, second.csrfToken)
    assert.equal(protection.verifyChallenge({
        cookieValue: first.cookieValue,
        csrfToken: second.csrfToken,
    }), false)
    assert.equal(stats.challenges.length, 2)
    assert.deepEqual(stats.logs, [])
})

test('ignores client-supplied challenge values and does not replace the session cookie', async (t) => {
    const { get, stats, protection } = await startFixture(t)
    const injectedNonce = 'a'.repeat(43)
    const result = await get({
        query: `?cookieValue=${injectedNonce}&csrfToken=attacker&expiresAt=9999999999`,
        cookie: `p32_login_csrf_dev=${injectedNonce}; p32_session_dev=old.jwt.value`,
    })
    // assertChallenge ตรวจว่ามี Set-Cookie เดียวและเป็นชื่อ challenge เท่านั้น
    const pair = assertChallenge(result, protection)
    assert.notEqual(pair.cookieValue, injectedNonce)
    assert.equal(pair.cookieValue, stats.challenges[0].cookieValue)
    assert.notEqual(pair.csrfToken, 'attacker')
    assert.deepEqual(stats.logs, [])
})

test('handles challenge creation failure without setting a cookie or exposing private details', async (t) => {
    const { get, stats } = await startFixture(t, {
        challengeError: new Error('TEST_ONLY_PRIVATE_CHALLENGE_DETAIL'),
    })
    assertSafeError(await get(), stats)
    assert.equal(stats.challenges.length, 0)
    assert.equal(stats.cookieCalls, 0)
})

test('handles a cookie helper failure without returning a challenge token', async (t) => {
    const { get, stats } = await startFixture(t, {
        cookieError: new Error('TEST_ONLY_PRIVATE_COOKIE_DETAIL'),
    })
    assertSafeError(await get(), stats)
    assert.equal(stats.challenges.length, 1)
    assert.equal(stats.cookieCalls, 1)
})

test('rejects protection dependencies without a createChallenge function', () => {
    for (const loginCsrfProtection of [undefined, null, {}, { createChallenge: 123 }]) {
        assert.throws(() => createLoginCsrfController({
            loginCsrfProtection,
            loginCsrfCookie: { setChallengeCookie() { } },
        }), TypeError)
    }
})

test('rejects cookie dependencies without a setChallengeCookie function', () => {
    for (const loginCsrfCookie of [undefined, null, {}, { setChallengeCookie: 123 }]) {
        assert.throws(() => createLoginCsrfController({
            loginCsrfProtection: { createChallenge() { } },
            loginCsrfCookie,
        }), TypeError)
    }
})
