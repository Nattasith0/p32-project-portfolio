import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { readAuthConfig } from '../src/config/auth.config.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'

// ข้อมูลสมมติสำหรับตรวจ cookie เท่านั้น
const testToken = 'cookie.test.token'
const expiresAt = new Date('2030-01-01T00:30:00Z')

function cookieSettings(environment = 'development') {
    return readAuthConfig({
        NODE_ENV: environment,
        P32_JWT_SECRET_HEX: '11'.repeat(32),
        P32_CSRF_SECRET_HEX: '22'.repeat(32),
        P32_WEB_ORIGIN: environment === 'production'
            ? 'https://p32.example.test'
            : 'http://localhost:5173',
    }).cookie
}

async function requestCookie(t, settings, action) {
    const cookies = createSessionCookie(settings)
    const app = express()

    app.get('/cookie', (request, response) => {
        action(cookies, response)
        response.status(204).end()
    })

    // พอร์ต 0 ให้ระบบเลือกพอร์ตว่าง ไม่ใช้พอร์ต Backend 3001
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

    const response = await fetch(
        `http://127.0.0.1:${server.address().port}/cookie`,
        { signal: AbortSignal.timeout(5000) }
    )

    assert.equal(response.status, 204)

    const headers = response.headers.getSetCookie()
    assert.equal(headers.length, 1)

    const [pair, ...parts] = headers[0]
        .split(';')
        .map((part) => part.trim())

    const attributes = new Map(parts.map((part) => {
        const separator = part.indexOf('=')

        if (separator === -1) {
            return [part.toLowerCase(), true]
        }

        return [
            part.slice(0, separator).toLowerCase(),
            part.slice(separator + 1),
        ]
    }))

    return { pair, attributes }
}

function assertCookiePolicy(attributes, secure) {
    assert.equal(attributes.get('path'), '/')
    assert.equal(attributes.get('httponly'), true)
    assert.equal(attributes.get('samesite'), 'Lax')
    assert.equal(attributes.has('secure'), secure)
    assert.equal(attributes.has('domain'), false)
    assert.equal(attributes.has('max-age'), false)
}

test('sets the expected development and HTTPS cookie headers', async (t) => {
    for (const environment of ['development', 'production']) {
        const secure = environment === 'production'
        const name = secure ? '__Host-p32_session' : 'p32_session_dev'

        const result = await requestCookie(
            t,
            cookieSettings(environment),
            (cookies, response) => {
                cookies.setSessionCookie(response, {
                    token: testToken,
                    expiresAt,
                })
            }
        )

        assert.equal(result.pair, `${name}=${testToken}`)
        assertCookiePolicy(result.attributes, secure)

        assert.equal(
            result.attributes.get('expires'),
            expiresAt.toUTCString()
        )
    }
})

test('clears cookies with matching scope and a past expiration', async (t) => {
    for (const environment of ['development', 'production']) {
        const secure = environment === 'production'
        const name = secure ? '__Host-p32_session' : 'p32_session_dev'

        const result = await requestCookie(
            t,
            cookieSettings(environment),
            (cookies, response) => {
                cookies.clearSessionCookie(response)
            }
        )

        assert.equal(result.pair, `${name}=`)
        assertCookiePolicy(result.attributes, secure)

        assert.ok(
            Date.parse(result.attributes.get('expires')) < Date.now()
        )
    }
})

test('rejects cookie settings that violate the policy', () => {
    const valid = cookieSettings()

    const invalidSettings = [
        undefined,
        null,
        {},
        { ...valid, name: 'unexpected_cookie' },
        { ...valid, options: {} },
        { ...valid, options: { ...valid.options, httpOnly: false } },
        { ...valid, options: { ...valid.options, secure: undefined } },
        { ...valid, options: { ...valid.options, secure: true } },
        { ...valid, options: { ...valid.options, sameSite: 'none' } },
        { ...valid, options: { ...valid.options, path: '/api' } },
        { ...valid, options: { ...valid.options, domain: 'example.test' } },
    ]

    for (const settings of invalidSettings) {
        assert.throws(() => createSessionCookie(settings), TypeError)
    }
})

test('rejects invalid token inputs and expiration dates before writing', () => {
    const cookies = createSessionCookie(cookieSettings())
    let writes = 0

    const response = {
        cookie() {
            writes += 1
        },
    }

    for (const token of [
        undefined, null, 123, {}, '', 'a'.repeat(4097),
    ]) {
        assert.throws(() => cookies.setSessionCookie(response, {
            token,
            expiresAt,
        }), TypeError)
    }

    for (const invalidDate of [
        undefined,
        null,
        '2030-01-01',
        new Date(NaN),
        new Date(-1000),
        new Date(expiresAt.getTime() + 1),
    ]) {
        assert.throws(() => cookies.setSessionCookie(response, {
            token: testToken,
            expiresAt: invalidDate,
        }), TypeError)
    }

    assert.equal(writes, 0)
})

test('rejects responses without the required Express methods', () => {
    const cookies = createSessionCookie(cookieSettings())

    for (const response of [
        undefined, null, {}, { cookie: 123, clearCookie: 123 },
    ]) {
        assert.throws(() => cookies.setSessionCookie(response, {
            token: testToken,
            expiresAt,
        }), TypeError)

        assert.throws(
            () => cookies.clearSessionCookie(response),
            TypeError
        )
    }
})

test('keeps cookie policy and expiration isolated from mutation', () => {
    const settings = cookieSettings()
    const cookies = createSessionCookie(settings)
    const expiration = new Date(expiresAt.getTime())

    settings.name = 'changed_cookie'
    settings.options.httpOnly = false
    settings.options.secure = true
    settings.options.path = '/changed'

    const writes = []

    const response = {
        cookie(name, token, options) {
            writes.push({
                name,
                token,
                options: structuredClone(options),
            })

            // จำลองผู้รับแก้ object ที่ได้รับ
            options.httpOnly = false
            options.expires.setTime(0)

            return this
        },
    }

    const input = { token: testToken, expiresAt: expiration }

    assert.equal(cookies.setSessionCookie(response, input), response)
    assert.equal(cookies.setSessionCookie(response, input), response)

    assert.equal(writes.length, 2)
    assert.deepEqual(writes[0], writes[1])
    assert.equal(writes[0].name, 'p32_session_dev')

    assert.deepEqual(writes[0].options, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        expires: expiresAt,
    })

    assert.equal(expiration.getTime(), expiresAt.getTime())
})