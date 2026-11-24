import test from 'node:test'
import assert from 'node:assert/strict'
import { login, AuthApiError } from '../src/api/authApi.ts'

const user = {
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    username: 'student_demo',
    displayName: 'ผู้ใช้ทดสอบ',
}

const input = {
    username: ' Student_Demo ',
    password: ' TEST_ONLY_PASSWORD ',
}

const token = `1793675400.${'a'.repeat(43)}`
const requestId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

function jsonResponse(body, status = 200, headers = {}) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json', ...headers },
    })
}

function mockLogin(t, response) {
    const calls = []

    t.mock.method(globalThis, 'fetch', async (url, options) => {
        calls.push({ url, options })

        return url === '/api/v1/auth/login-csrf'
            ? jsonResponse({ csrfToken: token })
            : response
    })

    return calls
}

test('requests a challenge before posting credentials and returns only safe user fields', async (t) => {
    const controller = new AbortController()
    const calls = mockLogin(t, jsonResponse({
        user: { ...user, password_hash: 'TEST_ONLY_HASH' },
    }))

    assert.deepEqual(
        await login({ ...input, role: 'system_admin' }, controller.signal),
        user,
    )

    assert.deepEqual(calls.map((call) => call.url), [
        '/api/v1/auth/login-csrf',
        '/api/v1/auth/login',
    ])

    for (const { options } of calls) {
        assert.equal(options.credentials, 'same-origin')
        assert.equal(options.cache, 'no-store')
        assert.equal(options.redirect, 'error')
        assert.equal(options.signal, controller.signal)
    }

    assert.equal(calls[1].options.method, 'POST')
    assert.equal(calls[1].options.headers['X-CSRF-Token'], token)
    assert.equal(calls[1].options.headers['Content-Type'], 'application/json')
    assert.deepEqual(JSON.parse(calls[1].options.body), input)
})

test('does not send credentials if obtaining a valid challenge fails', async (t) => {
    let response
    const urls = []

    t.mock.method(globalThis, 'fetch', async (url) => {
        urls.push(url)
        return response
    })

    for (response of [
        jsonResponse({}, 500),
        jsonResponse({}),
        jsonResponse({ csrfToken: 1 }),
        jsonResponse({ csrfToken: '' }),
        jsonResponse({ csrfToken: 'x'.repeat(65) }),
        jsonResponse({ csrfToken: 'invalid\n' }),
    ]) {
        urls.length = 0
        await assert.rejects(login(input))
        assert.deepEqual(urls, ['/api/v1/auth/login-csrf'])
    }
})

test('reports invalid credentials without retrying or exposing the server message', async (t) => {
    const calls = mockLogin(t, jsonResponse({
        code: 'INVALID_CREDENTIALS',
        message: 'TEST_PRIVATE_MESSAGE',
    }, 401, { 'X-Request-Id': requestId }))

    await assert.rejects(login(input), (error) => {
        assert.ok(error instanceof AuthApiError)
        assert.equal(error.status, 401)
        assert.equal(error.code, 'INVALID_CREDENTIALS')
        assert.equal(error.requestId, requestId)
        assert.equal(error.retryAfter, null)
        assert.equal(error.message.includes('TEST_PRIVATE_MESSAGE'), false)
        return true
    })

    assert.equal(calls.length, 2)
})

test('preserves the rate limit code and Retry-After without retrying the password', async (t) => {
    const calls = mockLogin(t, jsonResponse({
        code: 'LOGIN_RATE_LIMITED',
    }, 429, { 'Retry-After': '60' }))

    await assert.rejects(login(input), (error) => {
        assert.ok(error instanceof AuthApiError)
        assert.equal(error.status, 429)
        assert.equal(error.code, 'LOGIN_RATE_LIMITED')
        assert.equal(error.retryAfter, 60)
        return true
    })

    assert.equal(calls.length, 2)
})

test('handles non-JSON errors and rejects malformed error metadata', async (t) => {
    let response

    t.mock.method(globalThis, 'fetch', async (url) => {
        return url.endsWith('/login-csrf')
            ? jsonResponse({ csrfToken: token })
            : response
    })

    for (response of [
        new Response('<html>proxy failure</html>', { status: 500 }),
        jsonResponse({ code: 'invalid code' }, 503, {
            'X-Request-Id': 'invalid',
            'Retry-After': '-1',
        }),
    ]) {
        await assert.rejects(login(input), (error) => {
            assert.ok(error instanceof AuthApiError)
            assert.equal(error.code, 'AUTH_REQUEST_FAILED')
            assert.equal(error.requestId, null)
            assert.equal(error.retryAfter, null)
            return true
        })
    }
})

test('rejects an invalid successful login response', async (t) => {
    mockLogin(t, jsonResponse({ user: null }))
    await assert.rejects(login(input), /Invalid current user response/)
})

test('preserves network and abort failures at either request stage', async (t) => {
    let calls, failOn, failure

    t.mock.method(globalThis, 'fetch', async () => {
        calls += 1
        if (calls === failOn) throw failure
        return jsonResponse({ csrfToken: token })
    })

    for (failOn of [1, 2]) {
        for (failure of [
            new TypeError('TEST_NETWORK'),
            new DOMException('TEST_ABORT', 'AbortError'),
        ]) {
            calls = 0
            await assert.rejects(login(input), (error) => error === failure)
        }
    }
})

test('rejects invalid input types before making a request', async (t) => {
    t.mock.method(globalThis, 'fetch', () => {
        assert.fail('Unexpected request')
    })

    for (const value of [
        undefined,
        null,
        {},
        { username: 1, password: 'x' },
        { username: 'x', password: 1 },
    ]) {
        await assert.rejects(login(value), TypeError)
    }
})