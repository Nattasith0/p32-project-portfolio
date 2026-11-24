import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { createLogoutController } from '../src/modules/auth/logout.controller.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

const identity = {
    sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
}
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

async function startFixture(t, {
    secure = false,
    revokeResult = true,
    repositoryError,
    cookieError,
} = {}) {
    const stats = { calls: [], events: [], clearCalls: 0, logs: [] }
    const sessionRepository = {
        async revokeSession(context) {
            stats.calls.push(context)
            stats.events.push('revoke')
            if (repositoryError) throw repositoryError
            return revokeResult
        },
    }
    const realCookie = createSessionCookie({
        name: secure ? '__Host-p32_session' : 'p32_session_dev',
        options: {
            httpOnly: true,
            secure,
            sameSite: 'lax',
            path: '/',
        },
    })
    const controller = createLogoutController({
        sessionRepository,
        sessionCookie: {
            clearSessionCookie(response) {
                stats.clearCalls += 1
                stats.events.push('clear')
                if (cookieError) throw cookieError
                return realCookie.clearSessionCookie(response)
            },
        },
    })

    const app = express()
    app.use(requestContext)
    app.use(express.json({ limit: 1024 }))

    // จำลอง identity เฉพาะ tests ของ controller
    // การตรวจ Origin/session/CSRF จะทดสอบร่วมกับ router จริงในขั้นถัดไป
    app.post('/logout', (request, response, next) => {
        request.auth = { ...identity }
        next()
    }, controller.logout)
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
    const url = `http://127.0.0.1:${server.address().port}/logout`

    async function post() {
        const response = await fetch(
            `${url}?sessionId=attacker-session&userId=attacker-user`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    sessionId: 'body-session',
                    userId: 'body-user',
                    auth: { sessionId: 'body-session', userId: 'body-user' },
                }),
                signal: AbortSignal.timeout(5000),
            },
        )
        const text = await response.text()
        return { response, text, body: text ? JSON.parse(text) : null }
    }

    return { post, stats }
}

function assertSuccessfulLogout({ response, text }) {
    assert.equal(response.status, 204)
    assert.equal(text, '')
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.match(response.headers.get('x-request-id'), UUID_PATTERN)
}

function assertClearedCookie(response, secure) {
    const cookie = response.headers.get('set-cookie')
    const name = secure ? '__Host-p32_session' : 'p32_session_dev'

    assert.ok(cookie.startsWith(`${name}=;`))
    assert.match(cookie, /; Path=\/(?:;|$)/)
    assert.match(cookie, /; HttpOnly(?:;|$)/)
    assert.match(cookie, /; SameSite=Lax(?:;|$)/)
    assert.doesNotMatch(cookie, /; (?:Domain|Max-Age)=/i)

    if (secure) {
        assert.match(cookie, /; Secure(?:;|$)/)
    } else {
        assert.doesNotMatch(cookie, /; Secure(?:;|$)/)
    }

    const expiration = /; Expires=([^;]+)/i.exec(cookie)
    assert.ok(expiration)
    assert.equal(Date.parse(expiration[1]), 0)
}

function assertSafeError({ response, body }, stats) {
    const requestId = response.headers.get('x-request-id')
    assert.equal(response.status, 500)
    assert.match(requestId, UUID_PATTERN)
    assert.equal(response.headers.get('cache-control'), 'no-store')
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

test('revokes only the authenticated session and clears the development cookie with HTTP 204', async (t) => {
    const { post, stats } = await startFixture(t)
    const result = await post()

    assertSuccessfulLogout(result)
    assertClearedCookie(result.response, false)
    assert.deepEqual(stats.calls, [{ ...identity }])
    assert.deepEqual(stats.events, ['revoke', 'clear'])
    assert.equal(stats.clearCalls, 1)
    assert.deepEqual(stats.logs, [])
})

test('clears an HTTPS-policy cookie with the matching host-only scope', async (t) => {
    const { post, stats } = await startFixture(t, { secure: true })
    const result = await post()

    assertSuccessfulLogout(result)
    assertClearedCookie(result.response, true)
    assert.deepEqual(stats.events, ['revoke', 'clear'])
    assert.deepEqual(stats.logs, [])
})

test('clears the cookie if another request already revoked the session', async (t) => {
    const { post, stats } = await startFixture(t, { revokeResult: false })
    const result = await post()

    assertSuccessfulLogout(result)
    assertClearedCookie(result.response, false)
    assert.deepEqual(stats.calls, [{ ...identity }])
    assert.deepEqual(stats.events, ['revoke', 'clear'])
})

test('does not clear the cookie or report success when revocation fails', async (t) => {
    const { post, stats } = await startFixture(t, {
        repositoryError: new Error('TEST_ONLY_PRIVATE_DATABASE_DETAIL'),
    })
    const result = await post()

    assertSafeError(result, stats)
    assert.equal(result.response.headers.get('set-cookie'), null)
    assert.equal(stats.clearCalls, 0)
    assert.deepEqual(stats.events, ['revoke'])
})

test('forwards a cookie helper failure after revocation without reporting success', async (t) => {
    const { post, stats } = await startFixture(t, {
        cookieError: new Error('TEST_ONLY_PRIVATE_COOKIE_DETAIL'),
    })
    const result = await post()

    assertSafeError(result, stats)
    assert.equal(result.response.headers.get('set-cookie'), null)
    assert.deepEqual(stats.calls, [{ ...identity }])
    assert.deepEqual(stats.events, ['revoke', 'clear'])
})

test('waits for revocation to finish before clearing the cookie and ending the response', async () => {
    const events = []
    let finishRevocation
    const pendingRevocation = new Promise((resolve) => {
        finishRevocation = resolve
    })
    const controller = createLogoutController({
        sessionRepository: {
            async revokeSession(context) {
                assert.deepEqual(context, identity)
                events.push('revoke-start')
                await pendingRevocation
                events.push('revoke-done')
                return true
            },
        },
        sessionCookie: {
            clearSessionCookie() {
                events.push('clear')
            },
        },
    })
    const response = {
        set(name, value) {
            assert.equal(name, 'Cache-Control')
            assert.equal(value, 'no-store')
            return this
        },
        status(value) {
            assert.equal(value, 204)
            events.push('status')
            return this
        },
        end() {
            events.push('end')
            return this
        },
    }

    const completion = controller.logout({ auth: identity }, response)
    assert.deepEqual(events, ['revoke-start'])

    finishRevocation()
    await completion
    assert.deepEqual(events, ['revoke-start', 'revoke-done', 'clear', 'status', 'end'])
})

test('rejects a repository without a revokeSession function', () => {
    for (const sessionRepository of [undefined, null, {}, { revokeSession: 123 }]) {
        assert.throws(() => createLogoutController({
            sessionRepository,
            sessionCookie: { clearSessionCookie() {} },
        }), TypeError)
    }
})

test('rejects a cookie helper without a clearSessionCookie function', () => {
    for (const sessionCookie of [undefined, null, {}, { clearSessionCookie: 123 }]) {
        assert.throws(() => createLogoutController({
            sessionRepository: { async revokeSession() { return true } },
            sessionCookie,
        }), TypeError)
    }
})
