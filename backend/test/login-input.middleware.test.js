import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request as httpRequest } from 'node:http'
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib'
import express from 'express'
import { MemoryStore } from 'express-rate-limit'
import { createLoginJsonParser, validateLoginRequest } from '../src/modules/auth/login-input.middleware.js'
import { createLoginRateLimiter } from '../src/modules/auth/login-rate-limit.middleware.js'
import { createLoginCsrfProtection } from '../src/security/login-csrf.js'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'
import { createRequireLoginCsrf } from '../src/modules/auth/login-csrf.middleware.js'
import { createRequireOrigin } from '../src/middleware/origin.middleware.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

const WEB_ORIGIN = 'http://localhost:5173'
const FIXED_TIME = Date.parse('2026-11-03T03:00:00.987Z')
const LIMIT_BYTES = 16 * 1024
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const validBody = JSON.stringify({ username: 'student_demo', password: ' TEST_ONLY_PASSWORD ' })

async function startFixture(t, { limit = 100 } = {}) {
    const stats = { inputs: [], logs: [] }
    const protection = createLoginCsrfProtection({
        secretHex: '11'.repeat(32), now: () => FIXED_TIME,
    })
    const challenge = protection.createChallenge()
    const cookies = createLoginCsrfCookie({
        httpOnly: true, secure: false, sameSite: 'lax', path: '/',
    })
    const store = new MemoryStore()
    const app = express()
    app.use(requestContext)
    // เส้นทางจำลอง ใช้ middleware จริงตามลำดับที่จะประกอบ HTTP login
    app.post('/login-check',
        createRequireOrigin({ webOrigin: WEB_ORIGIN }),
        createLoginRateLimiter({ limit, store }),
        createRequireLoginCsrf({ loginCsrfCookie: cookies, loginCsrfProtection: protection }),
        createLoginJsonParser(),
        validateLoginRequest,
        (request, response) => {
            // เก็บเฉพาะใน fixture เพื่อ assert ไม่ส่งรหัสผ่านกลับ client หรือ log
            stats.inputs.push(request.loginInput)
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
            store.shutdown()
        }
    })
    await once(server, 'listening')
    const url = `http://127.0.0.1:${server.address().port}/login-check`

    function send({
        origin = WEB_ORIGIN,
        token = challenge.csrfToken,
        contentType = 'application/json',
        encoding,
        body = validBody,
        chunked = false,
    } = {}) {
        const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8')
        const headers = { Cookie: `p32_login_csrf_dev=${challenge.cookieValue}` }
        if (origin !== null) headers.Origin = origin
        if (token !== null) headers['X-CSRF-Token'] = token
        if (contentType !== null) headers['Content-Type'] = contentType
        if (encoding !== undefined) headers['Content-Encoding'] = encoding
        if (chunked) headers['Transfer-Encoding'] = 'chunked'
        else headers['Content-Length'] = bytes.length

        return new Promise((resolve, reject) => {
            const request = httpRequest(url, {
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
            if (chunked) {
                request.write(bytes.subarray(0, Math.floor(bytes.length / 2)))
                request.end(bytes.subarray(Math.floor(bytes.length / 2)))
            } else request.end(bytes)
        })
    }
    return { send, stats }
}

function assertFailure(result, status, code, message) {
    assert.equal(result.status, status)
    assert.match(result.headers['x-request-id'], UUID_PATTERN)
    assert.equal(result.headers['cache-control'], 'no-store')
    assert.equal(result.headers['set-cookie'], undefined)
    assert.deepEqual(result.body, { code, message, request_id: result.headers['x-request-id'] })
}

function assertUnsupported(result) {
    assertFailure(result, 415, 'UNSUPPORTED_MEDIA_TYPE', 'รูปแบบข้อมูลคำขอไม่รองรับ')
}

function assertInvalidInput(result) {
    assertFailure(result, 400, 'INVALID_LOGIN_INPUT', 'ข้อมูลเข้าสู่ระบบไม่ถูกต้อง')
}

test('normalizes username while preserving password spaces and the parsed body', async (t) => {
    const { send, stats } = await startFixture(t)
    const input = { username: ' Student_Demo ', password: ' TEST_ONLY_PASSWORD ' }
    const result = await send({ body: JSON.stringify(input) })
    assert.equal(result.status, 204)
    assert.equal(result.body, null)
    assert.equal(result.headers['cache-control'], 'no-store')
    assert.deepEqual(stats.inputs, [{ username: 'student_demo', password: input.password }])
    assert.deepEqual(input, { username: ' Student_Demo ', password: ' TEST_ONLY_PASSWORD ' })
    assert.deepEqual(stats.logs, [])
})

test('accepts Unicode length boundaries including fully escaped emoji JSON', async (t) => {
    const { send, stats } = await startFixture(t)
    const input = { username: '😀'.repeat(128), password: '😀'.repeat(1024) }
    const escaped = JSON.stringify(input).replace(/[\u0080-\uffff]/g,
        (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`)
    assert.ok(Buffer.byteLength(escaped, 'utf8') < LIMIT_BYTES)
    assert.equal((await send({ body: escaped })).status, 204)
    assert.deepEqual(stats.inputs, [input])
})

test('rejects missing or unsupported Content-Type values', async (t) => {
    const { send, stats } = await startFixture(t)
    for (const contentType of [
        null, '', 'text/plain', 'text/json', 'application/x-www-form-urlencoded',
        'multipart/form-data; boundary=test', 'application/problem+json',
    ]) assertUnsupported(await send({ contentType }))
    assert.deepEqual(stats.inputs, [])
    assert.deepEqual(stats.logs, [])
})

test('accepts JSON with UTF-8 parameters and rejects unsupported charsets', async (t) => {
    const { send, stats } = await startFixture(t)
    for (const contentType of ['application/json; charset=utf-8', 'Application/JSON; charset="UTF-8"']) {
        assert.equal((await send({ contentType })).status, 204)
    }
    assertUnsupported(await send({ contentType: 'application/json; charset=iso-8859-1' }))
    assert.equal(stats.inputs.length, 2)
    assert.deepEqual(stats.logs, [])
})

test('accepts exactly 16 KiB and rejects one extra byte with Content-Length', async (t) => {
    const { send, stats } = await startFixture(t)
    const boundary = validBody + ' '.repeat(LIMIT_BYTES - Buffer.byteLength(validBody))
    assert.equal(Buffer.byteLength(boundary), LIMIT_BYTES)
    assert.equal((await send({ body: boundary })).status, 204)
    assertFailure(await send({ body: boundary + ' ' }),
        413, 'PAYLOAD_TOO_LARGE', 'ข้อมูลคำขอมีขนาดเกินกำหนด')
    assert.equal(stats.inputs.length, 1)
    assert.deepEqual(stats.logs, [])
})

test('enforces the same byte limit for chunked requests', async (t) => {
    const { send, stats } = await startFixture(t)
    assert.equal((await send({ chunked: true })).status, 204)
    const oversized = validBody + ' '.repeat(LIMIT_BYTES)
    assertFailure(await send({ body: oversized, chunked: true }),
        413, 'PAYLOAD_TOO_LARGE', 'ข้อมูลคำขอมีขนาดเกินกำหนด')
    assert.equal(stats.inputs.length, 1)
})

test('returns safe parser errors for malformed JSON or primitive JSON', async (t) => {
    const { send, stats } = await startFixture(t)
    for (const body of ['{"password":"TEST_ONLY_PRIVATE_PASSWORD",', 'null', 'true', '123', '"text"']) {
        const result = await send({ body })
        assertFailure(result, 400, 'INVALID_JSON', 'รูปแบบ JSON ไม่ถูกต้อง')
        assert.equal(JSON.stringify(result).includes('TEST_ONLY_PRIVATE_PASSWORD'), false)
    }
    assert.deepEqual(stats.inputs, [])
    assert.deepEqual(stats.logs, [])
})

test('rejects empty bodies, arrays and invalid login fields without reaching credentials', async (t) => {
    const { send, stats } = await startFixture(t)
    for (const body of [
        '', '{}', '[]', '{"username":"student_demo"}',
        '{"username":"student_demo","password":1}',
        '{"username":"student_demo","password":""}',
        '{"username":"student_demo","password":"x","role":"system_admin"}',
        JSON.stringify({ username: 'x'.repeat(129), password: 'x' }),
        JSON.stringify({ username: 'student_demo', password: 'x'.repeat(1025) }),
    ]) assertInvalidInput(await send({ body }))
    assert.deepEqual(stats.inputs, [])
    assert.deepEqual(stats.logs, [])
})

test('rejects compressed bodies instead of inflating login payloads', async (t) => {
    const { send, stats } = await startFixture(t)
    for (const [encoding, compress] of [
        ['gzip', gzipSync], ['deflate', deflateSync], ['br', brotliCompressSync],
    ]) assertUnsupported(await send({ encoding, body: compress(Buffer.from(validBody)) }))
    assert.equal((await send({ encoding: 'identity' })).status, 204)
    assert.equal(stats.inputs.length, 1)
    assert.deepEqual(stats.logs, [])
})

test('checks Origin, rate limit and login CSRF before parsing the body', async (t) => {
    const { send, stats } = await startFixture(t, { limit: 1 })
    assertFailure(await send({ origin: 'https://attacker.example', body: '{' }),
        403, 'ORIGIN_NOT_ALLOWED', 'ไม่อนุญาตคำขอจากแหล่งที่มานี้')
    assertFailure(await send({ token: 'invalid', body: '{' }),
        403, 'CSRF_INVALID', 'ไม่สามารถยืนยันคำขอได้')
    const limited = await send({ body: '{' })
    assertFailure(limited, 429, 'LOGIN_RATE_LIMITED',
        'มีคำขอเข้าสู่ระบบมากเกินไป กรุณาลองใหม่ภายหลัง')
    assert.ok(Number(limited.headers['retry-after']) > 0)
    assert.deepEqual(stats.inputs, [])
    assert.deepEqual(stats.logs, [])
})

test('clears stale login input and does not mutate the request body', () => {
    const body = { username: ' Student_Demo ', password: ' unchanged ' }
    const request = { body, loginInput: { username: 'stale' }, requestId: 'test-id' }
    let nextCalls = 0
    const response = {
        set() { return this },
        status(status) { this.statusCode = status; return this },
        json(value) { this.body = value; return this },
    }
    validateLoginRequest(request, response, () => { nextCalls += 1 })
    assert.equal(nextCalls, 1)
    assert.deepEqual(body, { username: ' Student_Demo ', password: ' unchanged ' })
    assert.deepEqual(request.loginInput, { username: 'student_demo', password: ' unchanged ' })
    assert.notEqual(request.loginInput, body)

    request.body = {}
    validateLoginRequest(request, response, () => { nextCalls += 1 })
    assert.equal(nextCalls, 1)
    assert.equal(request.loginInput, null)
    assert.equal(response.statusCode, 400)
    assert.equal(response.body.code, 'INVALID_LOGIN_INPUT')
})
