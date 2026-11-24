import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

// ข้อมูลสมมติสำหรับ tests เท่านั้น
const PRIVATE_MARKER = 'TEST_ONLY_PRIVATE_DATA'
const REQUEST_ID = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'

const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

function assertFailure(result, status, code, message) {
    const requestId = result.headers.get('x-request-id')

    assert.equal(result.statusCode, status)
    assert.equal(result.headers.get('cache-control'), 'no-store')
    assert.match(requestId, UUID_PATTERN)

    assert.deepEqual(result.body, {
        code,
        message,
        request_id: requestId,
    })

    assert.equal(
        JSON.stringify(result.body).includes(PRIVATE_MARKER),
        false,
    )
}

function assertInternalError(result) {
    assertFailure(
        result,
        500,
        'INTERNAL_ERROR',
        'เกิดข้อผิดพลาดภายในระบบ',
    )
}

function assertSafeLog(logs, requestId) {
    assert.deepEqual(logs, [
        [
            'P32 API request failed',
            {
                code: 'INTERNAL_ERROR',
                request_id: requestId,
            },
        ],
    ])
}

// ใช้ Express และ JSON parser จริงกับกรณี HTTP
async function startHttpFixture(t) {
    const logs = []
    const app = express()

    app.use(requestContext)

    // จำกัดขนาดให้เล็กเฉพาะ tests เพื่อทดสอบคำขอที่ใหญ่เกินกำหนด
    app.use(express.json({
        limit: 128,
        inflate: false,
    }))

    app.get('/fail', () => {
        const error = new Error(PRIVATE_MARKER)

        error.headers = {
            'X-Private-Debug': PRIVATE_MARKER,
        }

        throw error
    })

    app.post('/json', (request, response) => {
        response.json({ ok: true })
    })

    app.use(createApiErrorHandler({
        logger: {
            error(...args) {
                logs.push(args)
            },
        },
    }))

    const server = app.listen(0, '127.0.0.1')

    t.after(async () => {
        if (server.listening) {
            await new Promise((resolve, reject) => {
                server.close((error) => {
                    if (error) reject(error)
                    else resolve()
                })
            })
        }
    })

    await once(server, 'listening')

    const baseUrl = `http://127.0.0.1:${server.address().port}`

    async function send(path, options = {}) {
        const response = await fetch(`${baseUrl}${path}`, {
            ...options,
            signal: AbortSignal.timeout(5000),
        })

        return {
            statusCode: response.status,
            headers: response.headers,
            body: await response.json(),
        }
    }

    function post(body, headers = {}) {
        return send('/json', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...headers,
            },
            body,
        })
    }

    return { send, post, logs }
}

// จำลอง response สำหรับกรณีที่ตรวจตรงตัว middleware
function createDirectFixture(logger) {
    const logs = []

    const result = {
        statusCode: null,
        headers: new Map(),
        body: null,
    }

    const response = {
        headersSent: false,

        set(name, value) {
            result.headers.set(name.toLowerCase(), value)
            return this
        },

        status(value) {
            result.statusCode = value
            return this
        },

        json(body) {
            result.body = body
            this.headersSent = true
            return this
        },
    }

    const handler = createApiErrorHandler({
        logger: logger ?? {
            error(...args) {
                logs.push(args)
            },
        },
    })

    function run(error, request = { requestId: REQUEST_ID }) {
        handler(error, request, response, () => {
            assert.fail('An unsent response should be handled here')
        })

        return result
    }

    return { handler, response, result, logs, run }
}

test('returns a safe HTTP 500 and logs only the code and request ID', async (t) => {
    const fixture = await startHttpFixture(t)
    const result = await fixture.send('/fail')

    assertInternalError(result)

    assert.match(
        result.headers.get('content-type'),
        /^application\/json\b/,
    )

    assert.equal(result.headers.get('x-private-debug'), null)

    assertSafeLog(
        fixture.logs,
        result.body.request_id,
    )
})

test('returns HTTP 400 for malformed JSON without logging its body', async (t) => {
    const fixture = await startHttpFixture(t)

    const result = await fixture.post(
        `{"password":"${PRIVATE_MARKER}",}`,
    )

    assertFailure(
        result,
        400,
        'INVALID_JSON',
        'รูปแบบ JSON ไม่ถูกต้อง',
    )

    assert.deepEqual(fixture.logs, [])
})

test('returns HTTP 413 when the JSON body exceeds the limit', async (t) => {
    const fixture = await startHttpFixture(t)

    const result = await fixture.post(JSON.stringify({
        password: `${'x'.repeat(256)}${PRIVATE_MARKER}`,
    }))

    assertFailure(
        result,
        413,
        'PAYLOAD_TOO_LARGE',
        'ข้อมูลคำขอมีขนาดเกินกำหนด',
    )

    assert.deepEqual(fixture.logs, [])
})

test('returns HTTP 415 for unsupported charset and content encoding', async (t) => {
    const fixture = await startHttpFixture(t)

    const headersToCheck = [
        {
            'Content-Type': 'application/json; charset=unsupported',
        },
        {
            'Content-Encoding': 'unsupported',
        },
    ]

    for (const headers of headersToCheck) {
        const result = await fixture.post('{}', headers)

        assertFailure(
            result,
            415,
            'UNSUPPORTED_MEDIA_TYPE',
            'รูปแบบข้อมูลคำขอไม่รองรับ',
        )
    }

    assert.deepEqual(fixture.logs, [])
})

test('recognizes only known Error types with matching status codes', () => {
    const knownError = Object.assign(new Error(PRIVATE_MARKER), {
        type: 'request.size.invalid',
        status: 400,
    })

    const knownFixture = createDirectFixture()

    assertFailure(
        knownFixture.run(knownError),
        400,
        'INVALID_REQUEST',
        'ข้อมูลคำขอไม่ถูกต้อง',
    )

    assert.deepEqual(knownFixture.logs, [])

    const unknownErrors = [
        Object.assign(new Error(PRIVATE_MARKER), {
            status: 418,
            expose: true,
        }),
        Object.assign(new Error(PRIVATE_MARKER), {
            type: 'entity.parse.failed',
            status: 500,
        }),
        Object.assign(new Error(PRIVATE_MARKER), {
            type: '__proto__',
            status: 400,
        }),
        {
            type: 'entity.parse.failed',
            status: 400,
            message: PRIVATE_MARKER,
        },
        PRIVATE_MARKER,
        null,
        undefined,
    ]

    for (const error of unknownErrors) {
        const fixture = createDirectFixture()
        const result = fixture.run(error)

        assertInternalError(result)
        assertSafeLog(fixture.logs, REQUEST_ID)
    }
})

test('generates a request ID when the existing value is missing or invalid', () => {
    const invalidIds = [
        undefined,
        null,
        'not-a-uuid',
        'invalid\nrequest-id',
        123,
    ]

    for (const invalidId of invalidIds) {
        const fixture = createDirectFixture()
        const request = { requestId: invalidId }

        const result = fixture.run(
            new Error(PRIVATE_MARKER),
            request,
        )

        assertInternalError(result)

        assert.equal(request.requestId, result.body.request_id)
        assert.notEqual(request.requestId, invalidId)
        assertSafeLog(fixture.logs, request.requestId)
    }
})

test('still returns a safe error response when the logger throws', () => {
    const fixture = createDirectFixture({
        error() {
            throw new Error('TEST_ONLY_LOGGER_DETAIL')
        },
    })

    let result

    assert.doesNotThrow(() => {
        result = fixture.run(new Error(PRIVATE_MARKER))
    })

    assertInternalError(result)
    assert.equal(result.body.request_id, REQUEST_ID)

    assert.equal(
        JSON.stringify(result.body).includes('TEST_ONLY_LOGGER_DETAIL'),
        false,
    )
})

test('delegates the original error when response headers were already sent', () => {
    const fixture = createDirectFixture()
    const error = new Error(PRIVATE_MARKER)
    const delegatedErrors = []
    const nextResult = Symbol('next result')

    fixture.response.headersSent = true

    const returned = fixture.handler(
        error,
        { requestId: REQUEST_ID },
        fixture.response,
        (receivedError) => {
            delegatedErrors.push(receivedError)
            return nextResult
        },
    )

    assert.equal(returned, nextResult)
    assert.deepEqual(delegatedErrors, [error])
    assert.equal(fixture.result.headers.size, 0)
    assert.equal(fixture.result.statusCode, null)
    assert.equal(fixture.result.body, null)
    assert.deepEqual(fixture.logs, [])
})

test('rejects logger dependencies without an error function', () => {
    const invalidLoggers = [
        null,
        {},
        { error: 123 },
    ]

    for (const logger of invalidLoggers) {
        assert.throws(
            () => createApiErrorHandler({ logger }),
            TypeError,
        )
    }
})