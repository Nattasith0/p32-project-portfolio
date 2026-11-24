import test from 'node:test'
import assert from 'node:assert/strict'
import { createUserSearchController } from '../src/modules/users/user-search.controller.js'
import { UserSearchError } from '../src/modules/users/user-search.service.js'

const REQUEST_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const USER = Object.freeze({
  userId: '00000000-0000-4000-8000-000000000001',
  username: 'student_demo',
  displayName: 'นักศึกษาทดสอบ',
  isActive: true,
  emailVerified: true,
})
const request = (extra = {}) => ({
  requestId: REQUEST_ID,
  query: { q: 'student' },
  ...extra,
})
function response() {
  const result = { headers: {}, status: null, body: null }
  return {
    result,
    set(name, value) {
      result.headers[name] = value
      return this
    },
    status(value) {
      result.status = value
      return this
    },
    json(value) {
      result.body = value
      return this
    },
  }
}
const withResult = (result) =>
  createUserSearchController({ userSearchService: { searchUsers: async () => result } })

test('passes only query input and projects an independent public page with no-store', async () => {
  const query = Object.freeze({ q: 'student', limit: '1' })
  const source = Object.freeze({
    ...USER,
    email: 'PRIVATE_TEST_ONLY',
    passwordHash: 'PRIVATE_TEST_ONLY',
  })
  let received
  const controller = createUserSearchController({
    userSearchService: {
      async searchUsers(value) {
        received = value
        return {
          users: Object.freeze([source]),
          nextCursor: USER.userId,
          privateValue: 'PRIVATE_TEST_ONLY',
        }
      },
    },
  })
  const res = response()
  await controller.searchUsers(request({ query, body: { q: 'other' } }), res)
  assert.equal(received, query)
  assert.deepEqual(res.result, {
    headers: { 'Cache-Control': 'no-store' },
    status: 200,
    body: { users: [USER], nextCursor: USER.userId },
  })
  res.result.body.users[0].displayName = 'local change'
  assert.equal(source.displayName, USER.displayName)
})

test('returns a successful empty page without inventing a cursor', async () => {
  const res = response()
  await withResult({ users: [], nextCursor: null }).searchUsers(request(), res)
  assert.deepEqual(res.result.body, { users: [], nextCursor: null })
  assert.equal(res.result.status, 200)
})

test('does not write success while the service is still pending', async () => {
  let finish
  const controller = createUserSearchController({
    userSearchService: {
      searchUsers: () =>
        new Promise((resolve) => {
          finish = resolve
        }),
    },
  })
  const res = response()
  const pending = controller.searchUsers(request(), res)
  assert.equal(res.result.status, null)
  finish({ users: [], nextCursor: null })
  await pending
  assert.equal(res.result.status, 200)
})

test('maps only the known domain error to HTTP 400 without exposing input or the internal message', async () => {
  const failure = new UserSearchError()
  failure.message = 'PRIVATE_TEST_ONLY'
  const controller = createUserSearchController({
    userSearchService: {
      async searchUsers() {
        throw failure
      },
    },
  })
  const res = response()
  await controller.searchUsers(request(), res)
  assert.deepEqual(res.result.body, {
    code: 'INVALID_USER_SEARCH_INPUT',
    message: 'ข้อมูลการค้นหาบัญชีไม่ถูกต้อง',
    request_id: REQUEST_ID,
  })
  assert.equal(res.result.status, 400)
  assert.equal(res.result.headers['Cache-Control'], 'no-store')
})

test('propagates unknown errors and spoofed codes without writing a response', async () => {
  const altered = new UserSearchError()
  altered.code = 'UNKNOWN_TEST_ONLY'
  for (const failure of [
    new Error('PRIVATE_TEST_ONLY'),
    Object.assign(new Error('PRIVATE_TEST_ONLY'), {
      code: 'INVALID_USER_SEARCH_INPUT',
    }),
    { code: 'INVALID_USER_SEARCH_INPUT' },
    altered,
  ]) {
    const controller = createUserSearchController({
      userSearchService: {
        async searchUsers() {
          throw failure
        },
      },
    })
    const res = response()
    await assert.rejects(
      controller.searchUsers(request(), res),
      (error) => error === failure,
    )
    assert.equal(res.result.status, null)
    assert.equal(res.result.body, null)
  }
})

test('rejects malformed public response containers and cursor metadata before success', async () => {
  for (const result of [
    undefined,
    null,
    [],
    {},
    { users: 'invalid', nextCursor: null },
    { users: [], nextCursor: undefined },
    { users: [], nextCursor: USER.userId },
    { users: [USER], nextCursor: 'invalid' },
    { users: [USER], nextCursor: '00000000-0000-4000-8000-000000000002' },
    { users: Array(51).fill(USER), nextCursor: null },
  ]) {
    const res = response()
    await assert.rejects(withResult(result).searchUsers(request(), res), TypeError)
    assert.equal(res.result.status, null)
    assert.equal(res.result.body, null)
  }
})

test('rejects malformed, duplicate or unsorted users and sparse arrays', async () => {
  const badUsers = [
    null,
    [],
    {},
    { ...USER, userId: USER.userId + '\n' },
    { ...USER, username: 2 },
    { ...USER, displayName: ' ' },
    { ...USER, isActive: 1 },
    { ...USER, emailVerified: false },
  ]
  const second = { ...USER, userId: '00000000-0000-4000-8000-000000000002' }
  for (const users of [
    ...badUsers.map((user) => [user]),
    [USER, USER],
    [second, USER],
    new Array(1),
  ]) {
    const res = response()
    await assert.rejects(
      withResult({ users, nextCursor: null }).searchUsers(request(), res),
      TypeError,
    )
    assert.equal(res.result.status, null)
  }
})

test('requires a server request ID before invoking the service', async () => {
  let calls = 0
  const controller = createUserSearchController({
    userSearchService: {
      async searchUsers() {
        calls += 1
        return { users: [], nextCursor: null }
      },
    },
  })
  for (const requestId of [undefined, '', 'invalid', REQUEST_ID + '\n']) {
    await assert.rejects(
      controller.searchUsers(request({ requestId }), response()),
      TypeError,
    )
  }
  assert.equal(calls, 0)
})

test('requires a search service dependency', () => {
  assert.throws(() => createUserSearchController(), TypeError)
  for (const userSearchService of [null, {}, { searchUsers: true }]) {
    assert.throws(() => createUserSearchController({ userSearchService }), TypeError)
  }
})
