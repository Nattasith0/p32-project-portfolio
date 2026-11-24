import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'

// ค่าสมมติสำหรับตรวจ cookie helper ไม่ใช่ข้อมูลเข้าสู่ระบบจริง
const NONCE = 'a'.repeat(43)
const OTHER_NONCE = 'b'.repeat(43)
const EXPIRES_MS = Date.parse('2030-01-01T00:10:00.000Z')

function cookieOptions(secure = false) {
    return { httpOnly: true, secure, sameSite: 'lax', path: '/' }
}

function cookieName(secure) {
    return secure ? '__Host-p32_login_csrf' : 'p32_login_csrf_dev'
}

async function requestCookie(t, secure, action) {
    const cookies = createLoginCsrfCookie(cookieOptions(secure))
    const app = express()
    app.get('/cookie', (request, response) => {
        action(cookies, response)
        response.status(204).end()
    })
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

    const response = await fetch(
        `http://127.0.0.1:${server.address().port}/cookie`,
        { signal: AbortSignal.timeout(5000) },
    )
    assert.equal(response.status, 204)
    assert.equal(await response.text(), '')
    const headers = response.headers.getSetCookie()
    assert.equal(headers.length, 1)

    const [pair, ...parts] = headers[0].split(';').map((part) => part.trim())
    const attributes = new Map(parts.map((part) => {
        const separator = part.indexOf('=')
        return separator === -1
            ? [part.toLowerCase(), true]
            : [part.slice(0, separator).toLowerCase(), part.slice(separator + 1)]
    }))
    return { pair, attributes }
}

function assertPolicy(attributes, secure) {
    assert.equal(attributes.get('path'), '/')
    assert.equal(attributes.get('httponly'), true)
    assert.equal(attributes.get('samesite'), 'Lax')
    assert.equal(attributes.has('secure'), secure)
    assert.equal(attributes.has('domain'), false)
    assert.equal(attributes.has('max-age'), false)
}

test('sets a separate challenge cookie with the expected development and HTTPS-policy headers', async (t) => {
    for (const secure of [false, true]) {
        const result = await requestCookie(t, secure, (cookies, response) => {
            cookies.setChallengeCookie(response, {
                cookieValue: NONCE,
                expiresAt: new Date(EXPIRES_MS),
            })
        })
        assert.equal(result.pair, `${cookieName(secure)}=${NONCE}`)
        assertPolicy(result.attributes, secure)
        assert.equal(result.attributes.get('expires'), new Date(EXPIRES_MS).toUTCString())
    }
})

test('clears the challenge cookie with matching scope and an expired date', async (t) => {
    for (const secure of [false, true]) {
        const result = await requestCookie(t, secure, (cookies, response) => {
            cookies.clearChallengeCookie(response)
        })
        assert.equal(result.pair, `${cookieName(secure)}=`)
        assertPolicy(result.attributes, secure)
        assert.equal(Date.parse(result.attributes.get('expires')), 0)
    }
})

test('reads only its challenge cookie without confusing it with session or other-environment cookies', () => {
    for (const secure of [false, true]) {
        const cookies = createLoginCsrfCookie(cookieOptions(secure))
        const name = cookieName(secure)
        const otherName = cookieName(!secure)

        assert.equal(cookies.readChallengeCookie(
            `p32_session_dev=${OTHER_NONCE}; ${name}=${NONCE}; ${otherName}=${OTHER_NONCE}`
        ), NONCE)
        for (const header of [
            `p32_session_dev=${NONCE}`,
            `__Host-p32_session=${NONCE}`,
            `${otherName}=${NONCE}`,
            `${name}_extra=${NONCE}`,
            `${name.toUpperCase()}=${NONCE}`,
        ]) {
            assert.equal(cookies.readChallengeCookie(header), null)
        }
    }
})

test('decodes valid escaped nonce values and rejects invalid encodings', () => {
    const cookies = createLoginCsrfCookie(cookieOptions())
    assert.equal(cookies.readChallengeCookie(
        `p32_login_csrf_dev=%61${NONCE.slice(1)}`
    ), NONCE)
    for (const value of ['%FF', '%', `${NONCE}%0A`, `%3B${NONCE.slice(1)}`]) {
        assert.equal(cookies.readChallengeCookie(`p32_login_csrf_dev=${value}`), null)
    }
})

test('rejects duplicate challenge cookie names including matching values and empty-value combinations', () => {
    for (const secure of [false, true]) {
        const cookies = createLoginCsrfCookie(cookieOptions(secure))
        const name = cookieName(secure)
        for (const values of [
            [NONCE, NONCE], [NONCE, OTHER_NONCE], [OTHER_NONCE, NONCE],
            ['', NONCE], [NONCE, ''],
        ]) {
            assert.equal(cookies.readChallengeCookie(
                `${name}=${values[0]}; theme=dark; ${name}=${values[1]}`
            ), null)
        }
    }
})

test('rejects missing headers, invalid header types and malformed nonce values', () => {
    const cookies = createLoginCsrfCookie(cookieOptions())
    for (const header of [undefined, null, 123, [], {}, '', 'theme=dark']) {
        assert.equal(cookies.readChallengeCookie(header), null)
    }
    for (const value of [
        '', 'a'.repeat(42), 'a'.repeat(44), '!'.repeat(43),
        'ก'.repeat(43), 'header.payload.signature',
    ]) {
        assert.equal(cookies.readChallengeCookie(`p32_login_csrf_dev=${value}`), null)
    }
})

test('enforces the cookie header limit at exactly 8192 UTF-8 bytes', () => {
    const cookies = createLoginCsrfCookie(cookieOptions())
    const prefix = `p32_login_csrf_dev=${NONCE}; padding=`
    const remainingBytes = 8192 - Buffer.byteLength(prefix, 'utf8')
    const asciiHeader = prefix + 'x'.repeat(remainingBytes)

    assert.equal(Buffer.byteLength(asciiHeader, 'utf8'), 8192)
    assert.equal(cookies.readChallengeCookie(asciiHeader), NONCE)
    assert.equal(cookies.readChallengeCookie(asciiHeader + 'x'), null)

    const unicodeHeader = prefix +
        'ก'.repeat(Math.floor(remainingBytes / 3)) + 'x'.repeat(remainingBytes % 3)
    assert.equal(Buffer.byteLength(unicodeHeader, 'utf8'), 8192)
    assert.equal(cookies.readChallengeCookie(unicodeHeader), NONCE)
    assert.ok((unicodeHeader + 'ก').length < 8192)
    assert.equal(cookies.readChallengeCookie(unicodeHeader + 'ก'), null)
})

test('rejects options that violate the host-only cookie policy', () => {
    for (const options of [
        undefined, null, {},
        { ...cookieOptions(), secure: 'false' },
        { ...cookieOptions(), httpOnly: false },
        { ...cookieOptions(), sameSite: 'none' },
        { ...cookieOptions(), path: '/auth' },
        { ...cookieOptions(), domain: 'example.test' },
        { ...cookieOptions(), domain: undefined },
    ]) {
        assert.throws(() => createLoginCsrfCookie(options), TypeError)
    }
})

test('rejects invalid values, expiration dates and responses before writing a cookie', () => {
    const cookies = createLoginCsrfCookie(cookieOptions())
    let writes = 0
    const response = { cookie() { writes += 1 } }
    for (const cookieValue of [
        undefined, null, 123, [], '', 'a'.repeat(42), 'a'.repeat(44),
        '!'.repeat(43), `${NONCE}\n`,
    ]) {
        assert.throws(() => cookies.setChallengeCookie(response, {
            cookieValue, expiresAt: new Date(EXPIRES_MS),
        }), TypeError)
    }
    for (const expiresAt of [
        undefined, null, '2030-01-01', new Date(NaN), new Date(-1000), new Date(1),
    ]) {
        assert.throws(() => cookies.setChallengeCookie(response, {
            cookieValue: NONCE, expiresAt,
        }), TypeError)
    }
    assert.equal(writes, 0)

    for (const invalidResponse of [undefined, null, {}, { cookie: 123 }]) {
        assert.throws(() => cookies.setChallengeCookie(invalidResponse, {
            cookieValue: NONCE, expiresAt: new Date(EXPIRES_MS),
        }), TypeError)
    }
    for (const invalidResponse of [undefined, null, {}, { clearCookie: 123 }]) {
        assert.throws(() => cookies.clearChallengeCookie(invalidResponse), TypeError)
    }
})

test('isolates cookie policy and expiration dates from external mutation', () => {
    const options = cookieOptions()
    const cookies = createLoginCsrfCookie(options)
    options.secure = true
    options.httpOnly = false
    options.sameSite = 'none'
    options.path = '/changed'
    options.domain = 'attacker.example'

    const calls = []
    const response = {
        cookie(...args) { calls.push(args) },
        clearCookie(...args) { calls.push(args) },
    }
    const expiresAt = new Date(EXPIRES_MS)
    cookies.setChallengeCookie(response, { cookieValue: NONCE, expiresAt })
    expiresAt.setTime(0)
    assert.equal(calls[0][0], 'p32_login_csrf_dev')
    assert.equal(calls[0][2].expires.getTime(), EXPIRES_MS)
    assert.equal(calls[0][2].secure, false)

    calls[0][2].secure = true
    calls[0][2].sameSite = 'none'
    cookies.clearChallengeCookie(response)
    assert.equal(calls[1][0], 'p32_login_csrf_dev')
    assert.deepEqual(calls[1][1], cookieOptions())
})
