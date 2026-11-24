import test from 'node:test'
import assert from 'node:assert/strict'
import { logout, AuthApiError } from '../src/api/authApi.ts'

const csrfToken = 'a'.repeat(43)

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

test('gets a session CSRF token before logout and accepts empty HTTP 204', async (t) => {
  const calls = []
  const controller = new AbortController()
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url, options })
    return url === '/api/v1/auth/csrf'
      ? jsonResponse({ csrfToken })
      : new Response(null, { status: 204 })
  })

  assert.equal(await logout(controller.signal), undefined)
  assert.deepEqual(calls.map(({ url }) => url), [
    '/api/v1/auth/csrf', '/api/v1/auth/logout',
  ])
  for (const { options } of calls) {
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.signal, controller.signal)
    assert.equal(options.body, undefined)
  }
  assert.equal(calls[1].options.method, 'POST')
  assert.equal(calls[1].options.headers['X-CSRF-Token'], csrfToken)
})

test('treats an unauthenticated CSRF request as already signed out without POST', async (t) => {
  let count = 0
  t.mock.method(globalThis, 'fetch', async () => {
    count += 1
    return { status: 401, json: () => { throw new Error('Must not read body') } }
  })
  assert.equal(await logout(), undefined)
  assert.equal(count, 1)
})

test('accepts a session becoming unauthenticated between CSRF and logout', async (t) => {
  let count = 0
  t.mock.method(globalThis, 'fetch', async () => {
    count += 1
    return count === 1
      ? jsonResponse({ csrfToken })
      : { status: 401, json: () => { throw new Error('Must not read body') } }
  })
  assert.equal(await logout(), undefined)
  assert.equal(count, 2)
})

test('rejects malformed session tokens without sending logout', async (t) => {
  let token
  const urls = []
  t.mock.method(globalThis, 'fetch', async (url) => {
    urls.push(url)
    return jsonResponse({ csrfToken: token })
  })
  for (token of [undefined, null, 123, '', 'a'.repeat(42), 'a'.repeat(44),
    csrfToken + '\n', '.'.repeat(43), ' '.repeat(43)]) {
    urls.length = 0
    await assert.rejects(logout())
    assert.deepEqual(urls, ['/api/v1/auth/csrf'])
  }
})

test('propagates CSRF server failure without POST or exposing server text', async (t) => {
  const urls = []
  t.mock.method(globalThis, 'fetch', async (url) => {
    urls.push(url)
    return jsonResponse({ code: 'INTERNAL_ERROR', message: 'PRIVATE_TEST_DATA' }, 500)
  })
  await assert.rejects(logout(), (error) => {
    assert.ok(error instanceof AuthApiError)
    assert.equal(error.status, 500)
    assert.equal(error.message.includes('PRIVATE_TEST_DATA'), false)
    return true
  })
  assert.deepEqual(urls, ['/api/v1/auth/csrf'])
})

test('rejects denied, failed and unexpected successful logout responses without retrying', async (t) => {
  let status
  let count
  t.mock.method(globalThis, 'fetch', async () => {
    count += 1
    return count === 1 ? jsonResponse({ csrfToken }) : jsonResponse({}, status)
  })
  for (status of [200, 202, 403, 500]) {
    count = 0
    await assert.rejects(logout(), (error) => {
      assert.ok(error instanceof AuthApiError)
      assert.equal(error.status, status)
      return true
    })
    assert.equal(count, 2)
  }
})

test('preserves network and abort failures at either request stage', async (t) => {
  let failure
  let failOn
  let count
  t.mock.method(globalThis, 'fetch', async () => {
    count += 1
    if (count === failOn) throw failure
    return jsonResponse({ csrfToken })
  })
  for (failure of [new TypeError('Test network failure'), new DOMException('Test abort', 'AbortError')]) {
    for (failOn of [1, 2]) {
      count = 0
      await assert.rejects(logout(), (error) => error === failure)
      assert.equal(count, failOn)
    }
  }
})

test('rejects malformed CSRF JSON without sending logout', async (t) => {
  let count = 0
  t.mock.method(globalThis, 'fetch', async () => {
    count += 1
    return new Response('not-json', { status: 200 })
  })
  await assert.rejects(logout(), SyntaxError)
  assert.equal(count, 1)
})
