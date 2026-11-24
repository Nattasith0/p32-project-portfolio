import test from 'node:test'
import assert from 'node:assert/strict'
import { getRoleCatalog, RoleCatalogApiError } from '../src/api/rolesApi.ts'

const roles = [
  { roleCode: 'advisor', roleName: 'อาจารย์ที่ปรึกษา' },
  { roleCode: 'student', roleName: 'นักศึกษาในโครงงาน' },
]
const REQUEST_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

test('requests the role catalog through the proxy with cookies, no cache and cancellation', async (t) => {
  const controller = new AbortController()
  let calls = 0
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls += 1
    assert.equal(url, '/api/v1/admin/roles')
    assert.equal(options.method, 'GET')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.signal, controller.signal)
    assert.deepEqual(options.headers, { Accept: 'application/json' })
    assert.equal(options.body, undefined)
    return jsonResponse({ roles })
  })
  assert.deepEqual(await getRoleCatalog(controller.signal), roles)
  assert.equal(calls, 1)
})

test('projects new role objects without leaking fields or modifying the response object', async (t) => {
  const extraRoles = roles.map((role) => ({ ...role, privateData: 'PRIVATE_DETAIL' }))
  const payload = { roles: extraRoles, privateData: 'PRIVATE_DETAIL' }
  t.mock.method(globalThis, 'fetch', async () => ({
    status: 200,
    json: async () => payload,
  }))
  const result = await getRoleCatalog()
  assert.deepEqual(result, roles)
  assert.notEqual(result, extraRoles)
  assert.notEqual(result[0], extraRoles[0])
  assert.equal(extraRoles[0].privateData, 'PRIVATE_DETAIL')
})

test('accepts an empty catalog as a successful empty result', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => jsonResponse({ roles: [] }))
  assert.deepEqual(await getRoleCatalog(), [])
})

test('accepts valid role definitions from the server without inferring current-user privileges', async (t) => {
  const futureRole = {
    roleCode: 'lab_coordinator',
    roleName: 'ผู้ประสานงานห้องปฏิบัติการ',
  }
  t.mock.method(globalThis, 'fetch', async () => jsonResponse({ roles: [futureRole] }))
  assert.deepEqual(await getRoleCatalog(), [futureRole])
})

test('rejects invalid successful payloads and role field shapes', async (t) => {
  let payload
  t.mock.method(globalThis, 'fetch', async () => jsonResponse(payload))
  for (payload of [
    null,
    [],
    {},
    { roles: null },
    { roles: {} },
    { roles: [null] },
    { roles: [[]] },
    { roles: [{}] },
    { roles: [{ ...roles[0], roleCode: 1 }] },
    { roles: [{ ...roles[0], roleCode: '' }] },
    { roles: [{ ...roles[0], roleCode: 'Advisor' }] },
    { roles: [{ ...roles[0], roleCode: 'advisor\n' }] },
    { roles: [{ ...roles[0], roleCode: 'advisor<script>' }] },
    { roles: [{ ...roles[0], roleName: null }] },
    { roles: [{ ...roles[0], roleName: '   ' }] },
  ])
    await assert.rejects(getRoleCatalog(), TypeError)
})

test('rejects duplicate role codes and sparse arrays instead of rendering ambiguous rows', async (t) => {
  let payload
  t.mock.method(globalThis, 'fetch', async () => ({
    status: 200,
    json: async () => payload,
  }))
  for (payload of [{ roles: [roles[0], roles[0]] }, { roles: Array(1) }]) {
    await assert.rejects(getRoleCatalog(), TypeError)
  }
})

test('distinguishes unauthenticated and forbidden responses without reading server error text', async (t) => {
  let status
  t.mock.method(globalThis, 'fetch', async () => ({
    status,
    headers: new Headers({ 'X-Request-Id': REQUEST_ID }),
    json() {
      assert.fail('Must not read private server error text')
    },
  }))
  for (status of [401, 403]) {
    await assert.rejects(getRoleCatalog(), (error) => {
      assert.ok(error instanceof RoleCatalogApiError)
      assert.equal(error.status, status)
      assert.equal(error.requestId, REQUEST_ID)
      assert.equal(error.message, 'Role catalog request failed')
      return true
    })
  }
})

test('does not turn failures or unexpected successful statuses into an empty catalog or retry', async (t) => {
  let status
  let calls
  t.mock.method(globalThis, 'fetch', async () => {
    calls += 1
    return {
      status,
      headers: new Headers(),
      json() {
        assert.fail('Must not read error body')
      },
    }
  })
  for (status of [201, 204, 404, 429, 500, 502]) {
    calls = 0
    await assert.rejects(
      getRoleCatalog(),
      (error) => error instanceof RoleCatalogApiError && error.status === status,
    )
    assert.equal(calls, 1)
  }
})

test('retains only a well-formed UUID as the error request ID', async (t) => {
  let requestId
  t.mock.method(globalThis, 'fetch', async () => ({
    status: 500,
    headers: { get: () => requestId },
  }))
  for (requestId of [null, '', 'invalid', REQUEST_ID + '\n', 'x'.repeat(36)]) {
    await assert.rejects(
      getRoleCatalog(),
      (error) => error instanceof RoleCatalogApiError && error.requestId === null,
    )
  }
})

test('propagates malformed successful JSON for the interface to report as a failure', async (t) => {
  t.mock.method(
    globalThis,
    'fetch',
    async () => new Response('<html>Proxy error</html>', { status: 200 }),
  )
  await assert.rejects(getRoleCatalog(), SyntaxError)
})

test('preserves network and abort failures during fetch or successful body reading', async (t) => {
  let failure
  let duringBody
  t.mock.method(globalThis, 'fetch', async () => {
    if (!duringBody) throw failure
    return {
      status: 200,
      async json() {
        throw failure
      },
    }
  })
  for (failure of [
    new TypeError('TEST_NETWORK_FAILURE'),
    new DOMException('TEST_ABORT', 'AbortError'),
  ]) {
    for (duringBody of [false, true])
      await assert.rejects(getRoleCatalog(), (error) => error === failure)
  }
})
