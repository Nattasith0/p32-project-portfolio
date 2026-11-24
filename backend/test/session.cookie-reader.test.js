import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { readAuthConfig } from '../src/config/auth.config.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'

// รูปแบบ token สมมติสำหรับตรวจการอ่าน cookie ไม่ใช่ JWT จริง
const testToken = 'header.payload.signature'

function readerFor(environment = 'development') {
    const config = readAuthConfig({
        NODE_ENV: environment,
        P32_JWT_SECRET_HEX: '11'.repeat(32),
        P32_CSRF_SECRET_HEX: '22'.repeat(32),
        P32_WEB_ORIGIN: environment === 'production'
            ? 'https://p32.example.test'
            : 'http://localhost:5173',
    })

    return {
        name: config.cookie.name,
        cookies: createSessionCookie(config.cookie),
    }
}

test('reads only the configured session cookie', () => {
    for (const environment of ['development', 'production']) {
        const { name, cookies } = readerFor(environment)

        assert.equal(
            cookies.readSessionToken(
                `theme=dark; ${name}=${testToken}; language=th`
            ),
            testToken
        )
    }
})

test('decodes an encoded cookie value', () => {
    const { name, cookies } = readerFor()
    const encoded = testToken.replaceAll('.', '%2E')

    assert.equal(
        cookies.readSessionToken(`${name}=${encoded}`),
        testToken
    )
})

test('returns null for missing cookies or invalid header types', () => {
    const { cookies } = readerFor()

    for (const header of [
        undefined,
        null,
        123,
        [],
        {},
        '',
        'theme=dark',
        `p32_session_dev_extra=${testToken}`,
        `P32_SESSION_DEV=${testToken}`,
        `__Host-p32_session=${testToken}`,
    ]) {
        assert.equal(cookies.readSessionToken(header), null)
    }

    const production = readerFor('production')

    assert.equal(
        production.cookies.readSessionToken(
            `p32_session_dev=${testToken}`
        ),
        null
    )
})

test('rejects duplicate session cookie names', () => {
    for (const environment of ['development', 'production']) {
        const { name, cookies } = readerFor(environment)

        const duplicates = [
            `${name}=${testToken}; ${name}=${testToken}`,
            `${name}=${testToken}; theme=dark; ${name}=other.jwt.value`,
            `${name}=other.jwt.value; ${name}=${testToken}`,
            `${name}=${testToken.replaceAll('.', '%2E')}; ${name}=${testToken}`,
            `${name}=; ${name}=${testToken}`,
            `${name}=${testToken}; ${name}=`,
        ]

        for (const header of duplicates) {
            assert.equal(cookies.readSessionToken(header), null)
        }
    }
})

test('rejects empty or malformed token values', () => {
    const { name, cookies } = readerFor()

    for (const value of [
        '',
        'abc',
        'a.b',
        'a.b.c.d',
        'a.b.',
        'a..b',
        'a+b.c.d',
        'a/b.c.d',
        '"a.b.c"',
        '%E0%A4%A',
        'a%20b.c.d',
        'a%0Ab.c.d',
        'a.b.c%00',
        'ก.ข.ค',
    ]) {
        assert.equal(
            cookies.readSessionToken(`${name}=${value}`),
            null
        )
    }
})

test('enforces token length and header byte limits at their boundaries', () => {
    const { name, cookies } = readerFor()

    const maximumToken = 'a'.repeat(4092) + '.b.c'
    assert.equal(maximumToken.length, 4096)

    assert.equal(
        cookies.readSessionToken(`${name}=${maximumToken}`),
        maximumToken
    )

    assert.equal(
        cookies.readSessionToken(`${name}=a${maximumToken}`),
        null
    )

    const prefix = `${name}=${testToken}; padding=`
    const header = prefix + 'x'.repeat(
        8192 - Buffer.byteLength(prefix, 'utf8')
    )

    assert.equal(Buffer.byteLength(header, 'utf8'), 8192)
    assert.equal(cookies.readSessionToken(header), testToken)
    assert.equal(cookies.readSessionToken(header + 'x'), null)

    const multibyteHeader = prefix + 'ก'.repeat(3000)

    assert.ok(multibyteHeader.length < 8192)
    assert.ok(Buffer.byteLength(multibyteHeader, 'utf8') > 8192)
    assert.equal(cookies.readSessionToken(multibyteHeader), null)
})

test('reads cookies sent back through an Express HTTP request', async (t) => {
    const { cookies } = readerFor()
    const app = express()

    app.post('/set', (request, response) => {
        cookies.setSessionCookie(response, {
            token: testToken,
            expiresAt: new Date('2030-01-01T00:30:00Z'),
        })

        response.status(204).end()
    })

    app.get('/read', (request, response) => {
        response.json({
            recognized:
                cookies.readSessionToken(request.headers.cookie) === testToken,
        })
    })

    app.post('/clear', (request, response) => {
        cookies.clearSessionCookie(response)
        response.status(204).end()
    })

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

    const baseUrl = `http://127.0.0.1:${server.address().port}`

    function send(path, options = {}) {
        return fetch(baseUrl + path, {
            ...options,
            signal: AbortSignal.timeout(5000),
        })
    }

    async function read(cookieHeader) {
        const response = await send('/read', {
            headers: cookieHeader ? { Cookie: cookieHeader } : {},
        })

        assert.equal(response.status, 200)
        return response.json()
    }

    assert.deepEqual(await read(), { recognized: false })

    const setResponse = await send('/set', { method: 'POST' })
    assert.equal(setResponse.status, 204)

    const setHeaders = setResponse.headers.getSetCookie()
    assert.equal(setHeaders.length, 1)

    const cookiePair = setHeaders[0].split(';')[0]

    assert.deepEqual(await read(cookiePair), { recognized: true })
    assert.deepEqual(
        await read(`${cookiePair}; ${cookiePair}`),
        { recognized: false }
    )

    const clearResponse = await send('/clear', { method: 'POST' })
    assert.equal(clearResponse.status, 204)

    const clearHeaders = clearResponse.headers.getSetCookie()
    assert.equal(clearHeaders.length, 1)

    assert.deepEqual(
        await read(clearHeaders[0].split(';')[0]),
        { recognized: false }
    )
})