import test from 'node:test'
import assert from 'node:assert/strict'
import {
  createUserSearchService,
  UserSearchError,
} from '../src/modules/users/user-search.service.js'
import { createUserSearchRepository } from '../src/modules/users/user-search.repository.js'

const id = (number) => `00000000-0000-4000-8000-${String(number).padStart(12, '0')}`
const row = (number, extra = {}) => ({
  user_id: id(number),
  username: `student_${number}`,
  display_name: `นักศึกษาทดสอบ ${number}`,
  is_active: true,
  email_verified: true,
  ...extra,
})
const dto = (number, extra = {}) => ({
  userId: id(number),
  username: `student_${number}`,
  displayName: `นักศึกษาทดสอบ ${number}`,
  isActive: true,
  emailVerified: true,
  ...extra,
})
const serviceWithRows = (rows) =>
  createUserSearchService({
    userSearchRepository: { searchUsers: async () => rows },
  })

test('parses query values and returns only independent public DTOs without mutating input or rows', async () => {
  const query = Object.freeze({ q: '  Student  ', limit: '2', after: id(1) })
  const source = Object.freeze(
    row(2, { email: 'private@example.test', password_hash: 'PRIVATE_TEST_ONLY' }),
  )
  const rows = Object.freeze([source])
  let received
  const service = createUserSearchService({
    userSearchRepository: {
      async searchUsers(search) {
        received = search
        return rows
      },
    },
  })
  const result = await service.searchUsers(query)
  assert.deepEqual(received, { searchTerm: 'Student', limit: 2, after: id(1) })
  assert.deepEqual(result, { users: [dto(2)], nextCursor: null })
  result.users[0].displayName = 'changed locally'
  assert.equal(source.display_name, 'นักศึกษาทดสอบ 2')
  assert.equal(query.q, '  Student  ')
})

test('returns a successful empty page without a next cursor', async () => {
  assert.deepEqual(await serviceWithRows([]).searchUsers({ q: 'missing' }), {
    users: [],
    nextCursor: null,
  })
})

test('does not advertise another page when the result exactly fills the limit', async () => {
  assert.deepEqual(
    await serviceWithRows([row(1), row(2)]).searchUsers({ q: 'student', limit: '2' }),
    {
      users: [dto(1), dto(2)],
      nextCursor: null,
    },
  )
})

test('uses the last returned user as cursor and neither skips nor duplicates the lookahead on the next page', async () => {
  const searches = []
  const service = createUserSearchService({
    userSearchRepository: {
      async searchUsers(search) {
        searches.push(search)
        return search.after === null ? [row(1), row(2), row(3)] : [row(3), row(4)]
      },
    },
  })
  const first = await service.searchUsers({ q: 'student', limit: '2' })
  assert.deepEqual(first, { users: [dto(1), dto(2)], nextCursor: id(2) })
  const second = await service.searchUsers({
    q: 'student',
    limit: '2',
    after: first.nextCursor,
  })
  assert.deepEqual(second, { users: [dto(3), dto(4)], nextCursor: null })
  assert.deepEqual(
    [...first.users, ...second.users].map((user) => user.userId),
    [id(1), id(2), id(3), id(4)],
  )
  assert.equal(searches[1].after, id(2))
})

test('bounds default and maximum page sizes while preserving a lookahead cursor', async () => {
  for (const [query, limit] of [
    [{ q: 'student' }, 20],
    [{ q: 'student', limit: '50' }, 50],
  ]) {
    const result = await serviceWithRows(
      Array.from({ length: limit + 1 }, (_, i) => row(i + 1)),
    ).searchUsers(query)
    assert.equal(result.users.length, limit)
    assert.equal(result.nextCursor, id(limit))
  }
})

test('keeps inactive and unverified accounts visible without assigning permissions', async () => {
  const result = await serviceWithRows([
    row(1, { is_active: false, email_verified: false }),
    row(2, { is_active: false }),
  ]).searchUsers({ q: 'student' })
  assert.deepEqual(result.users, [
    dto(1, { isActive: false, emailVerified: false }),
    dto(2, { isActive: false }),
  ])
})

test('rejects invalid queries with a stable domain error before calling the repository', async () => {
  let calls = 0
  const service = createUserSearchService({
    userSearchRepository: {
      async searchUsers() {
        calls += 1
        return []
      },
    },
  })
  for (const query of [
    undefined,
    null,
    [],
    {},
    { q: 'x' },
    { q: ['student'] },
    { q: 'student', limit: '51' },
    { q: 'student', after: 'invalid' },
    { q: 'student', role: 'system_admin' },
  ]) {
    await assert.rejects(service.searchUsers(query), (error) => {
      assert.ok(error instanceof UserSearchError)
      assert.equal(error.code, 'INVALID_USER_SEARCH_INPUT')
      assert.equal(error.message, 'Invalid user search input')
      return true
    })
  }
  assert.equal(calls, 0)
})

test('rejects malformed containers and more than one lookahead row instead of truncating silently', async () => {
  for (const rows of [
    undefined,
    null,
    {},
    'invalid',
    [row(1), row(2), row(3), row(4)],
  ]) {
    await assert.rejects(
      serviceWithRows(rows).searchUsers({ q: 'student', limit: '2' }),
      TypeError,
    )
  }
})

test('rejects malformed rows including the otherwise hidden lookahead row', async () => {
  const invalidRows = [
    undefined,
    null,
    [],
    {},
    row(2, { user_id: 'invalid' }),
    row(2, { user_id: id(2) + '\n' }),
    row(2, { username: '' }),
    row(2, { username: 12 }),
    row(2, { display_name: '   ' }),
    row(2, { display_name: null }),
    row(2, { is_active: 1 }),
    row(2, { email_verified: 'true' }),
    row(2, { email_verified: false }),
  ]
  for (const invalid of invalidRows) {
    await assert.rejects(
      serviceWithRows([row(1), invalid]).searchUsers({ q: 'student', limit: '1' }),
      TypeError,
    )
  }
  await assert.rejects(
    serviceWithRows(new Array(1)).searchUsers({ q: 'student' }),
    TypeError,
  )
})

test('rejects duplicate, descending or pre-cursor user IDs', async () => {
  for (const rows of [
    [row(1), row(1)],
    [row(2), row(1)],
  ]) {
    await assert.rejects(serviceWithRows(rows).searchUsers({ q: 'student' }), TypeError)
  }
  for (const value of [1, 2]) {
    await assert.rejects(
      serviceWithRows([row(value)]).searchUsers({ q: 'student', after: id(2) }),
      TypeError,
    )
  }
})

test('normalizes UUID case when validating order and building public cursors', async () => {
  const first = '00000000-0000-4000-8000-0000000000AB'
  const second = '00000000-0000-4000-8000-0000000000AC'
  const result = await serviceWithRows([
    row(1, { user_id: first }),
    row(2, { user_id: second }),
  ]).searchUsers({ q: 'student', limit: '1' })
  assert.equal(result.users[0].userId, first.toLowerCase())
  assert.equal(result.nextCursor, first.toLowerCase())
  await assert.rejects(
    serviceWithRows([
      row(1, { user_id: first }),
      row(2, { user_id: first.toLowerCase() }),
    ]).searchUsers({ q: 'student' }),
    TypeError,
  )
})

test('captures pagination before awaiting and does not cache results between searches', async () => {
  const query = { q: 'student', limit: '1' }
  let calls = 0
  const service = createUserSearchService({
    userSearchRepository: {
      async searchUsers(search) {
        calls += 1
        query.limit = '50'
        search.limit = 50
        return calls === 1 ? [row(1), row(2)] : []
      },
    },
  })
  assert.deepEqual(await service.searchUsers(query), {
    users: [dto(1)],
    nextCursor: id(1),
  })
  assert.deepEqual(await service.searchUsers({ q: 'student' }), {
    users: [],
    nextCursor: null,
  })
  assert.equal(calls, 2)
})

test('propagates the original repository failure without retry or returning an empty page', async () => {
  const failure = new Error('TEST_ONLY_PRIVATE_DATABASE_ERROR')
  let calls = 0
  const service = createUserSearchService({
    userSearchRepository: {
      async searchUsers() {
        calls += 1
        throw failure
      },
    },
  })
  await assert.rejects(
    service.searchUsers({ q: 'student' }),
    (error) => error === failure,
  )
  assert.equal(calls, 1)
})

test('composes with the actual repository without interpolating search input into SQL', async () => {
  const repository = createUserSearchRepository({
    async query(sql, values) {
      assert.deepEqual(values, ['%a!%!_!!%', null, 2])
      assert.ok(!sql.includes('a%_!'))
      return { rows: [row(1), row(2)] }
    },
  })
  const service = createUserSearchService({ userSearchRepository: repository })
  assert.deepEqual(await service.searchUsers({ q: 'a%_!', limit: '1' }), {
    users: [dto(1)],
    nextCursor: id(1),
  })
})

test('rejects missing or invalid repository dependencies at construction', () => {
  assert.throws(() => createUserSearchService(), TypeError)
  for (const userSearchRepository of [null, {}, { searchUsers: true }]) {
    assert.throws(() => createUserSearchService({ userSearchRepository }), TypeError)
  }
})
