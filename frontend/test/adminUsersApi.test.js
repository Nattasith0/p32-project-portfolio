import test from 'node:test'
import assert from 'node:assert/strict'
import { AdminUsersApiError, getAdminUserRoles, searchAdminUsers } from '../src/api/adminUsersApi.ts'

const FIRST = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const SECOND = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const account = {
  userId: SECOND,
  username: 'faculty_demo',
  displayName: 'อาจารย์ทดสอบ',
  isActive: false,
  emailVerified: false,
}
const advisor = { roleCode: 'advisor', roleName: 'อาจารย์ที่ปรึกษา' }
const json = (body) => new Response(JSON.stringify(body), { status: 200 })

test('encodes search text and normalizes the cursor for a cancellable same-origin request', async (t) => {
  const signal = new AbortController().signal
  const q = 'ชื่อ &role=system_admin_% 🚀'
  t.mock.method(globalThis, 'fetch', async (path, options) => {
    const url = new URL(path, 'http://localhost:5173')
    assert.equal(url.pathname, '/api/v1/admin/users')
    assert.deepEqual([...url.searchParams], [['q', q], ['limit', '1'], ['after', FIRST]])
    assert.deepEqual(options, {
      method: 'GET', signal, credentials: 'same-origin', cache: 'no-store',
      redirect: 'error', headers: { Accept: 'application/json' },
    })
    return json({ users: [{ ...account, email: 'PRIVATE_TEST_DATA' }], nextCursor: SECOND })
  })
  assert.deepEqual(await searchAdminUsers({ q, limit: 1, after: FIRST.toUpperCase() }, signal), {
    users: [account], nextCursor: SECOND,
  })
})

test('accepts an empty search page and omits the cursor for a fresh search', async (t) => {
  t.mock.method(globalThis, 'fetch', async (path) => {
    assert.equal(path, '/api/v1/admin/users?q=demo&limit=20')
    return json({ users: [], nextCursor: null })
  })
  assert.deepEqual(await searchAdminUsers({ q: 'demo' }), { users: [], nextCursor: null })
})

test('rejects malformed pages, duplicate or regressing IDs and inconsistent cursors', async (t) => {
  let payload
  t.mock.method(globalThis, 'fetch', async () => json(payload))
  for (payload of [
    { users: [] },
    { users: [account, account], nextCursor: null },
    { users: [{ ...account, userId: FIRST }], nextCursor: null },
    { users: [account], nextCursor: FIRST },
    { users: [account], nextCursor: SECOND },
    { users: [{ ...account, isActive: true }], nextCursor: null },
    { users: [null], nextCursor: null },
  ]) {
    await assert.rejects(searchAdminUsers({ q: 'demo', limit: 2, after: FIRST }), TypeError)
  }
})

test('reads the normalized target and projects only the public account and role fields', async (t) => {
  const signal = new AbortController().signal
  t.mock.method(globalThis, 'fetch', async (path, options) => {
    assert.equal(path, `/api/v1/admin/users/${SECOND}/roles`)
    assert.equal(options.signal, signal)
    return json({ user: { ...account, email: 'PRIVATE_TEST_DATA' }, roles: [{ ...advisor, internal: true }] })
  })
  assert.deepEqual(await getAdminUserRoles(SECOND.toUpperCase(), signal), {
    user: account, roles: [advisor],
  })
})

test('accepts a roleless account and rejects cross-account or duplicate-role responses', async (t) => {
  let payload = { user: account, roles: [] }
  t.mock.method(globalThis, 'fetch', async () => json(payload))
  assert.deepEqual(await getAdminUserRoles(SECOND), { user: account, roles: [] })
  payload = { user: { ...account, userId: FIRST }, roles: [] }
  await assert.rejects(getAdminUserRoles(SECOND), TypeError)
  payload = { user: account, roles: [advisor, advisor] }
  await assert.rejects(getAdminUserRoles(SECOND), TypeError)
})

test('preserves HTTP status and validated request ID without reading the server error body', async (t) => {
  let status
  let requestId = FIRST
  t.mock.method(globalThis, 'fetch', async () => ({
    status,
    headers: new Headers({ 'X-Request-Id': requestId }),
    json() { assert.fail('Unexpected read of error body') },
  }))
  for (status of [400, 401, 403, 404, 500]) {
    await assert.rejects(getAdminUserRoles(SECOND), (error) =>
      error instanceof AdminUsersApiError && error.status === status && error.requestId === FIRST)
  }
  requestId = 'PRIVATE_TEST_DATA'
  await assert.rejects(searchAdminUsers({ q: 'demo' }), (error) =>
    error instanceof AdminUsersApiError && error.requestId === null)
})

test('rejects invalid cursor, target and search encoding before fetch', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => assert.fail('Unexpected fetch'))
  await assert.rejects(getAdminUserRoles('../roles'), TypeError)
  await assert.rejects(searchAdminUsers({ q: 'demo', after: 'invalid' }), TypeError)
  await assert.rejects(searchAdminUsers({ q: 'demo', limit: 51 }), TypeError)
  await assert.rejects(searchAdminUsers({ q: '\uD800' }), TypeError)
  await assert.rejects(searchAdminUsers({ q: 'a\0b' }), TypeError)
})
