import test from 'node:test'
import assert from 'node:assert/strict'
import { createUserSearchRepository } from '../src/modules/users/user-search.repository.js'

const AFTER = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

test('uses a parameterized SELECT with an explicit minimal projection and one lookahead row', async () => {
  const calls = []
  const rows = [
    {
      user_id: AFTER,
      username: 'admin_demo',
      display_name: 'ผู้ดูแล',
      is_active: true,
      email_verified: true,
    },
  ]
  const repository = createUserSearchRepository({
    async query(text, values) {
      calls.push({ text, values })
      return { rows }
    },
  })
  assert.equal(await repository.searchUsers({ searchTerm: 'admin', limit: 20 }), rows)
  assert.equal(calls.length, 1)
  assert.deepEqual(calls[0].values, ['%admin%', null, 21])
  assert.match(calls[0].text, /SELECT user_id, username, display_name, is_active/)
  assert.match(calls[0].text, /email_verified_at IS NOT NULL AS email_verified/)
  assert.doesNotMatch(
    calls[0].text,
    /SELECT\s+\*|password_hash|csrf|\bemail\s*,|OFFSET|COUNT\s*\(/i,
  )
})

test('passes the exclusive cursor and stable UUID order to the database', async () => {
  let seen
  const repository = createUserSearchRepository({
    async query(text, values) {
      seen = { text, values }
      return { rows: [] }
    },
  })
  assert.deepEqual(
    await repository.searchUsers({ searchTerm: 'student', limit: 1, after: AFTER }),
    [],
  )
  assert.deepEqual(seen.values, ['%student%', AFTER, 2])
  assert.match(seen.text, /user_id > \$2::uuid/)
  assert.match(seen.text, /ORDER BY user_id ASC/)
})

test('escapes LIKE metacharacters while preserving literal backslashes', async () => {
  let values
  const repository = createUserSearchRepository({
    async query(_text, params) {
      values = params
      return { rows: [] }
    },
  })
  for (const [searchTerm, pattern] of [
    ['50%', '%50!%%'],
    ['_demo', '%!_demo%'],
    ['a!b', '%a!!b%'],
    [String.raw`a\b`, String.raw`%a\b%`],
  ]) {
    await repository.searchUsers({ searchTerm, limit: 20 })
    assert.equal(values[0], pattern)
  }
})

test('keeps SQL-looking input entirely in parameters without changing the query text', async () => {
  const calls = []
  const repository = createUserSearchRepository({
    async query(text, values) {
      calls.push({ text, values })
      return { rows: [] }
    },
  })
  await repository.searchUsers({ searchTerm: 'admin', limit: 20 })
  const attack = "x' OR 1=1 --"
  await repository.searchUsers({ searchTerm: attack, limit: 20 })
  assert.equal(calls[0].text, calls[1].text)
  assert.equal(calls[1].text.includes(attack), false)
  assert.equal(calls[1].values[0], '%' + attack + '%')
})

test('caps database fetches at fifty result rows plus one lookahead', async () => {
  let values
  let calls = 0
  const repository = createUserSearchRepository({
    async query(_text, params) {
      calls += 1
      values = params
      return { rows: [] }
    },
  })
  await repository.searchUsers({ searchTerm: 'ab', limit: 50 })
  assert.equal(values[2], 51)
  for (const limit of [undefined, null, 0, 51, -1, 1.5, '20', NaN, Infinity]) {
    await assert.rejects(repository.searchUsers({ searchTerm: 'ab', limit }), TypeError)
  }
  await assert.rejects(repository.searchUsers({ searchTerm: {}, limit: 20 }), TypeError)
  assert.equal(calls, 1)
})

test('propagates database errors without retry or turning them into empty results', async () => {
  const failure = Object.assign(new Error('PRIVATE_DATABASE_DETAIL'), { code: '57014' })
  let calls = 0
  const repository = createUserSearchRepository({
    async query() {
      calls += 1
      throw failure
    },
  })
  await assert.rejects(
    repository.searchUsers({ searchTerm: 'ab', limit: 20 }),
    (error) => error === failure,
  )
  assert.equal(calls, 1)
})

test('rejects malformed database response shapes', async () => {
  for (const result of [undefined, null, {}, { rows: null }, { rows: {} }]) {
    const repository = createUserSearchRepository({ query: async () => result })
    await assert.rejects(
      repository.searchUsers({ searchTerm: 'ab', limit: 20 }),
      TypeError,
    )
  }
})

test('requires a database query executor', () => {
  for (const database of [undefined, null, {}, { query: true }]) {
    assert.throws(() => createUserSearchRepository(database), TypeError)
  }
})
