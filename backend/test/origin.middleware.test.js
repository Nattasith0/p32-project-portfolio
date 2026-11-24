import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request as httpRequest } from 'node:http'
import express from 'express'
import { createRequireOrigin } from '../src/middleware/origin.middleware.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

const WEB_ORIGIN = 'http://localhost:5173'
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

async function startFixture(t, webOrigin = WEB_ORIGIN) {
    const stats = { handled: 0, logs: [], hosts: [] }
    const app = express()

    app.use(requestContext)
    app.use((request, response, next) => {
        stats.hosts.push(request.headers.host)
        next()
    })
    app.use(createRequireOrigin({ webOrigin }))

    // ทดสอบด้วยว่า Origin ที่ไม่ผ่านถูกปฏิเสธก่อนอ่าน JSON
    app.use(express.json({ limit: 128 }))
    app.all('/probe', (request, response) => {
        stats.handled += 1
        response.status(204).end()
    })
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
    const url = `http://127.0.0.1:${server.address().port}/probe`

    // ใช้ node:http เพื่อทดสอบ Host และ Origin ซ้ำตามที่ส่งบนสายจริง
    function send(method, origin, { headers = {}, body } = {}) {
        const requestHeaders = { ...headers }
        if (origin !== undefined) requestHeaders.Origin = origin
        if (body !== undefined) {
            requestHeaders['Content-Length'] = Buffer.byteLength(body)
        }

        return new Promise((resolve, reject) => {
            const request = httpRequest(url, {
                method,
                headers: requestHeaders,
                agent: false,
                timeout: 5000,
            }, (response) => {
                const chunks = []

                response.on('error', reject)
                response.on('data', (chunk) => chunks.push(chunk))
                response.on('end', () => {
                    const text = Buffer.concat(chunks).toString('utf8')

                    try {
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
            request.on('timeout', () => {
                request.destroy(new Error('Test request timed out'))
            })
            request.end(body)
        })
    }

    return { send, stats }
}

function assertForbidden(result) {
    const requestId = result.headers['x-request-id']

    assert.equal(result.status, 403)
    assert.match(requestId, UUID_PATTERN)
    assert.equal(result.headers['cache-control'], 'no-store')
    assert.deepEqual(result.body, {
        code: 'ORIGIN_NOT_ALLOWED',
        message: 'ไม่อนุญาตคำขอจากแหล่งที่มานี้',
        request_id: requestId,
    })
}

test('lets safe methods pass the Origin check without a trusted Origin', async (t) => {
    const { send, stats } = await startFixture(t)

    for (const method of ['GET', 'HEAD', 'OPTIONS']) {
        for (const origin of [undefined, 'https://attacker.example']) {
            assert.equal((await send(method, origin)).status, 204)
        }
    }

    assert.equal(stats.handled, 6)
    assert.deepEqual(stats.logs, [])
})

test('allows state-changing methods only with the configured HTTP or HTTPS Origin', async (t) => {
    for (const webOrigin of [WEB_ORIGIN, 'https://p32.example.test']) {
        const { send, stats } = await startFixture(t, webOrigin)

        for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
            const result = await send(method, webOrigin)
            assert.equal(result.status, 204)
            assert.equal(result.headers['cache-control'], 'no-store')
        }

        assert.equal(stats.handled, 4)
        assert.deepEqual(stats.logs, [])
    }
})

test('rejects missing, empty and opaque Origins for state-changing requests', async (t) => {
    const { send, stats } = await startFixture(t)

    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        for (const origin of [undefined, '', 'null']) {
            assertForbidden(await send(method, origin))
        }
    }

    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('rejects scheme, host, port, suffix and non-canonical Origin mismatches', async (t) => {
    const { send, stats } = await startFixture(t)
    const origins = [
        'https://localhost:5173',
        'http://127.0.0.1:5173',
        'http://localhost:5174',
        'http://localhost.attacker.test:5173',
        `${WEB_ORIGIN}@attacker.test`,
        `${WEB_ORIGIN}/`,
        `${WEB_ORIGIN}/path`,
        `${WEB_ORIGIN}?next=1`,
        'http://LOCALHOST:5173',
    ]

    for (const origin of origins) {
        assertForbidden(await send('POST', origin))
    }

    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('rejects duplicate Origin headers even when their values match', async (t) => {
    const { send, stats } = await startFixture(t)

    assertForbidden(await send('POST', [WEB_ORIGIN, WEB_ORIGIN]))
    assert.equal(stats.handled, 0)
})

test('uses configured Origin instead of client-supplied Host or forwarded headers', async (t) => {
    const { send, stats } = await startFixture(t)

    assertForbidden(await send('POST', 'https://attacker.example', {
        headers: {
            Host: 'localhost:5173',
            'X-Forwarded-Host': 'localhost:5173',
            'X-Forwarded-Proto': 'http',
        },
    }))
    assert.equal(stats.hosts[0], 'localhost:5173')
    assert.equal(stats.handled, 0)

    const valid = await send('POST', WEB_ORIGIN, {
        headers: { Host: 'attacker.example' },
    })
    assert.equal(valid.status, 204)
    assert.equal(stats.hosts[1], 'attacker.example')
    assert.equal(stats.handled, 1)
})

test('rejects an untrusted Origin before parsing a malformed JSON body', async (t) => {
    const { send, stats } = await startFixture(t)
    const options = {
        headers: { 'Content-Type': 'application/json' },
        body: '{"broken":',
    }

    assertForbidden(await send('POST', 'https://attacker.example', options))

    const trusted = await send('POST', WEB_ORIGIN, options)
    assert.equal(trusted.status, 400)
    assert.equal(trusted.body.code, 'INVALID_JSON')
    assert.equal(stats.handled, 0)
    assert.deepEqual(stats.logs, [])
})

test('rejects invalid or non-canonical configured origins before serving requests', () => {
    for (const webOrigin of [
        undefined, null, 123, '', 'not-an-origin', 'null',
        'ftp://localhost', `${WEB_ORIGIN}/`, `${WEB_ORIGIN}/path`,
        `${WEB_ORIGIN}?query=1`, `${WEB_ORIGIN}#fragment`,
        'http://user:password@localhost:5173', 'http://LOCALHOST:5173',
    ]) {
        assert.throws(() => createRequireOrigin({ webOrigin }), TypeError)
    }
})
