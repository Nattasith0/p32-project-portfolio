import test from 'node:test'
import assert from 'node:assert/strict'
import { getCurrentUser } from '../src/api/authApi.ts'

const user = {
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    username: 'student_demo',
    displayName: 'ผู้ใช้ทดสอบ',
}

function jsonResponse(body, status = 200) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
    })
}

test('requests the current user through the proxy with cookies and cancellation', async (t) => {
    const controller = new AbortController()

    t.mock.method(globalThis, 'fetch', async (url, options) => {
        assert.equal(url, '/api/v1/auth/me')
        assert.equal(options.credentials, 'same-origin')
        assert.equal(options.cache, 'no-store')
        assert.equal(options.signal, controller.signal)
        assert.deepEqual(options.headers, {
            Accept: 'application/json',
        })

        return jsonResponse({ user })
    })

    assert.deepEqual(await getCurrentUser(controller.signal), user)
})

test('returns null for HTTP 401 without reading the error body', async (t) => {
    t.mock.method(
        globalThis,
        'fetch',
        async () => new Response('', { status: 401 }),
    )

    assert.equal(await getCurrentUser(), null)
})

test('does not treat server failures as an ordinary logged-out state', async (t) => {
    t.mock.method(globalThis, 'fetch', async () => jsonResponse({}, 500))

    await assert.rejects(
        getCurrentUser(),
        /Current user request failed/,
    )
})

test('rejects invalid successful response shapes', async (t) => {
    let body

    t.mock.method(globalThis, 'fetch', async () => jsonResponse(body))

    for (body of [
        null,
        {},
        { user: null },
        { user: [] },
        { user: { ...user, userId: 1 } },
        { user: { ...user, username: null } },
        { user: { ...user, displayName: undefined } },
    ]) {
        await assert.rejects(
            getCurrentUser(),
            /Invalid current user response/,
        )
    }
})

test('returns only the user fields used by the interface', async (t) => {
    t.mock.method(globalThis, 'fetch', async () => jsonResponse({
        user: {
            ...user,
            password_hash: 'TEST_ONLY_PRIVATE_HASH',
            roles: ['system_admin'],
        },
    }))

    assert.deepEqual(await getCurrentUser(), user)
})

test('rejects malformed JSON instead of returning a logged-out state', async (t) => {
    t.mock.method(
        globalThis,
        'fetch',
        async () => new Response('<html>test</html>'),
    )

    await assert.rejects(getCurrentUser(), SyntaxError)
})

test('preserves network and cancellation failures for the caller to handle', async (t) => {
    let failure

    t.mock.method(globalThis, 'fetch', async () => {
        throw failure
    })

    for (failure of [
        new TypeError('TEST_NETWORK_FAILURE'),
        new DOMException('TEST_ABORT', 'AbortError'),
    ]) {
        await assert.rejects(
            getCurrentUser(),
            (error) => error === failure,
        )
    }
})