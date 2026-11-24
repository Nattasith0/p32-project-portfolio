import test from 'node:test'
import assert from 'node:assert/strict'
import { changeUserRole, RoleChangeApiError } from '../src/api/roleChangeApi.ts'

const targetUserId = '00000000-0000-4000-8000-000000000002'
const auditId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const csrfToken = 'a'.repeat(43)
const input = { targetUserId, roleCode: 'advisor', action: 'assign', reason: ' ทดสอบบทบาท ' }

test('uses the session CSRF token and only the four role-change fields', async (t) => {
  const calls = []
  const { signal } = new AbortController()
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url, options })
    return calls.length === 1
      ? Response.json({ csrfToken })
      : Response.json({ changed: true, auditId, privateField: true })
  })
  assert.deepEqual(await changeUserRole({ ...input, actorUserId: 'ignored' }, signal), { changed: true, auditId })
  assert.deepEqual(calls.map(({ url }) => url), ['/api/v1/auth/csrf', '/api/v1/admin/role-changes'])
  for (const { options } of calls) {
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.signal, signal)
  }
  assert.equal(calls[1].options.method, 'POST')
  assert.equal(calls[1].options.headers['X-CSRF-Token'], csrfToken)
  assert.deepEqual(JSON.parse(calls[1].options.body), { ...input, reason: input.reason.trim() })
})

test('stops before POST when the session is expired or the token is malformed', async (t) => {
  const mock = t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 401 }))
  await assert.rejects(changeUserRole(input), (error) => error instanceof RoleChangeApiError && error.status === 401)
  mock.mock.mockImplementation(async () => Response.json({ csrfToken: 'bad token' }))
  await assert.rejects(changeUserRole(input), /Invalid session CSRF/)
  assert.equal(mock.mock.callCount(), 2)
  assert.ok(mock.mock.calls.every(({ arguments: [url] }) => url === '/api/v1/auth/csrf'))
})

test('rejects invalid local input before requesting a token', async (t) => {
  const mock = t.mock.method(globalThis, 'fetch')
  for (const changes of [
    { targetUserId: 'invalid' }, { roleCode: 'invalid code' }, { action: 'delete' },
    { reason: '  ' }, { reason: '😃'.repeat(501) }, { reason: '\0' }, { reason: '\uD800' },
  ]) {
    await assert.rejects(changeUserRole({ ...input, ...changes }), TypeError)
  }
  assert.equal(mock.mock.callCount(), 0)
})

test('validates changed and no-op responses without repeating the POST', async (t) => {
  let result = { changed: false, auditId: null }
  const mock = t.mock.method(globalThis, 'fetch', async (url) =>
    Response.json(url.endsWith('/csrf') ? { csrfToken } : result))
  assert.deepEqual(await changeUserRole(input), result)
  result = { changed: true, auditId: null }
  await assert.rejects(changeUserRole(input), TypeError)
  assert.equal(mock.mock.callCount(), 4)
})

test('retains allowlisted error metadata and never retries a failed mutation', async (t) => {
  const mock = t.mock.method(globalThis, 'fetch', async (url) =>
    url.endsWith('/csrf')
      ? Response.json({ csrfToken })
      : Response.json({ code: 'ROLE_CHANGE_BUSY', message: 'private error' }, {
          status: 409, headers: { 'x-request-id': auditId },
        }))
  await assert.rejects(changeUserRole(input), (error) =>
    error instanceof RoleChangeApiError && error.status === 409 &&
    error.code === 'ROLE_CHANGE_BUSY' && error.requestId === auditId && !error.message.includes('private error'))
  assert.equal(mock.mock.callCount(), 2)
})
