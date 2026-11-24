import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { createUserSearchRuntimeRepository } from '../src/modules/users/user-search.runtime.repository.js'
import {
  createUserSearchService,
  UserSearchError,
} from '../src/modules/users/user-search.service.js'

const INPUT = Object.freeze({ searchTerm: 'student%_!', limit: 2, after: null })
const ROW = Object.freeze({
  user_id: '00000000-0000-4000-8000-000000000001',
  username: 'student_demo',
  display_name: 'นักศึกษาทดสอบ',
  is_active: true,
  email_verified: true,
})

function fixture({
  rows = [ROW],
  failAt,
  failure,
  rollbackFailure,
  completion,
  waitForRollback,
  emitAt,
  connectionError,
} = {}) {
  const client = new EventEmitter()
  const calls = []
  const releases = []
  let acquisitions = 0
  client.query = async (config) => {
    calls.push(config)
    const phase = config.text.includes('FROM p32.users') ? 'search' : config.text
    if (phase === failAt) throw failure
    if (phase === emitAt) client.emit('error', connectionError)
    if (phase === 'search') return { rows }
    if (phase === 'ROLLBACK') {
      if (waitForRollback) await waitForRollback
      if (rollbackFailure) throw rollbackFailure
      return completion === undefined ? { command: 'ROLLBACK' } : completion
    }
    return { rows: [] }
  }
  client.release = (discard) => {
    releases.push(discard)
  }
  const pool = {
    async connect() {
      acquisitions += 1
      return client
    },
    query() {
      assert.fail('all transaction queries must use the checked-out client')
    },
  }
  return { pool, client, calls, releases, acquisitions: () => acquisitions }
}

test('bounds a read-only search on one client and restores settings before reusing the connection', async () => {
  const state = fixture()
  const result = await createUserSearchRuntimeRepository(state.pool).searchUsers(INPUT)
  assert.deepEqual(result, [ROW])
  const texts = state.calls.map((call) => call.text)
  assert.deepEqual(texts.slice(0, 4), [
    'BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY',
    "SET LOCAL statement_timeout = '5s'",
    "SET LOCAL lock_timeout = '2s'",
    "SET LOCAL idle_in_transaction_session_timeout = '15s'",
  ])
  assert.match(texts[4], /FROM p32\.users/)
  assert.deepEqual(state.calls[4].values, ['%student!%!_!!%', null, 3])
  assert.equal(texts[5], 'ROLLBACK')
  assert.equal(texts.length, 6)
  assert.ok(state.calls.every((call) => call.query_timeout === 10000))
  assert.deepEqual(state.releases, [false])
  assert.equal(state.acquisitions(), 1)
  assert.equal(state.client.listenerCount('error'), 0)
})

test('does not return results or release the client until transaction cleanup is acknowledged', async () => {
  let finishRollback
  const waitForRollback = new Promise((resolve) => {
    finishRollback = resolve
  })
  const state = fixture({ waitForRollback })
  let settled = false
  const search = createUserSearchRuntimeRepository(state.pool).searchUsers(INPUT)
  search.then(() => {
    settled = true
  })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(settled, false)
  assert.deepEqual(state.releases, [])
  finishRollback()
  assert.deepEqual(await search, [ROW])
  assert.deepEqual(state.releases, [false])
})

test('returns an empty search result only after successful cleanup', async () => {
  const state = fixture({ rows: [] })
  assert.deepEqual(
    await createUserSearchRuntimeRepository(state.pool).searchUsers(INPUT),
    [],
  )
  assert.deepEqual(state.releases, [false])
})

test('propagates pool acquisition failure without retrying', async () => {
  const failure = new Error('TEST_ONLY_POOL_FAILURE')
  let calls = 0
  const repository = createUserSearchRuntimeRepository({
    async connect() {
      calls += 1
      throw failure
    },
  })
  await assert.rejects(repository.searchUsers(INPUT), (error) => error === failure)
  assert.equal(calls, 1)
})

test('never starts a search when beginning the transaction or setting a deadline fails', async () => {
  for (const failAt of [
    'BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY',
    "SET LOCAL statement_timeout = '5s'",
    "SET LOCAL lock_timeout = '2s'",
    "SET LOCAL idle_in_transaction_session_timeout = '15s'",
  ]) {
    const failure = new Error('TEST_ONLY_SETUP_FAILURE')
    const state = fixture({ failAt, failure })
    await assert.rejects(
      createUserSearchRuntimeRepository(state.pool).searchUsers(INPUT),
      (error) => error === failure,
    )
    assert.ok(!state.calls.some((call) => call.text.includes('FROM p32.users')))
    assert.deepEqual(state.releases, [true])
    assert.equal(state.calls.at(-1).text, 'ROLLBACK')
  }
})

test('propagates statement, lock and client query timeout errors without retry or an empty result', async () => {
  for (const code of ['57014', '55P03', 'TEST_ONLY_CLIENT_TIMEOUT']) {
    const failure = Object.assign(new Error('TEST_ONLY_TIMEOUT'), { code })
    const state = fixture({ failAt: 'search', failure })
    await assert.rejects(
      createUserSearchRuntimeRepository(state.pool).searchUsers(INPUT),
      (error) => error === failure,
    )
    assert.equal(
      state.calls.filter((call) => call.text.includes('FROM p32.users')).length,
      1,
    )
    assert.deepEqual(state.releases, [true])
  }
})

test('rejects malformed repository output and discards the connection', async () => {
  const state = fixture({ rows: null })
  await assert.rejects(
    createUserSearchRuntimeRepository(state.pool).searchUsers(INPUT),
    TypeError,
  )
  assert.deepEqual(state.releases, [true])
  assert.equal(state.calls.at(-1).text, 'ROLLBACK')
})

test('does not return a successful read when ROLLBACK fails and does not retry cleanup', async () => {
  const failure = new Error('TEST_ONLY_ROLLBACK_FAILURE')
  const state = fixture({ rollbackFailure: failure })
  await assert.rejects(
    createUserSearchRuntimeRepository(state.pool).searchUsers(INPUT),
    (error) => error === failure,
  )
  assert.equal(state.calls.filter((call) => call.text === 'ROLLBACK').length, 1)
  assert.deepEqual(state.releases, [true])
})

test('requires the expected cleanup command tag before reusing a client', async () => {
  for (const completion of [null, {}, { command: 'COMMIT' }]) {
    const state = fixture({ completion })
    await assert.rejects(
      createUserSearchRuntimeRepository(state.pool).searchUsers(INPUT),
      TypeError,
    )
    assert.deepEqual(state.releases, [true])
  }
})

test('preserves the original search error when cleanup also fails', async () => {
  const failure = new Error('TEST_ONLY_SEARCH_FAILURE')
  const state = fixture({
    failAt: 'search',
    failure,
    rollbackFailure: new Error('TEST_ONLY_CLEANUP_FAILURE'),
  })
  await assert.rejects(
    createUserSearchRuntimeRepository(state.pool).searchUsers(INPUT),
    (error) => error === failure,
  )
  assert.deepEqual(state.releases, [true])
})

test('rejects connection errors emitted while search or cleanup queries otherwise resolve', async () => {
  for (const emitAt of ['search', 'ROLLBACK']) {
    const connectionError = new Error('TEST_ONLY_CONNECTION_LOST')
    const state = fixture({ emitAt, connectionError })
    await assert.rejects(
      createUserSearchRuntimeRepository(state.pool).searchUsers(INPUT),
      (error) => error === connectionError,
    )
    assert.deepEqual(state.releases, [true])
    assert.equal(state.client.listenerCount('error'), 1)
    // listener รองรับ error ที่อาจมาช้าระหว่างปิด connection ที่ทิ้งแล้ว
    state.client.emit('error', new Error('TEST_ONLY_LATE_SOCKET_ERROR'))
  }
})

test('service validates queries before taking a pooled connection and still projects safe DTOs', async () => {
  const state = fixture()
  const service = createUserSearchService({
    userSearchRepository: createUserSearchRuntimeRepository(state.pool),
  })
  await assert.rejects(service.searchUsers({ q: 'x' }), UserSearchError)
  assert.equal(state.acquisitions(), 0)
  assert.deepEqual(await service.searchUsers({ q: 'student' }), {
    users: [
      {
        userId: ROW.user_id,
        username: ROW.username,
        displayName: ROW.display_name,
        isActive: true,
        emailVerified: true,
      },
    ],
    nextCursor: null,
  })
  assert.deepEqual(state.releases, [false])
})

test('concurrent searches use independent clients and transaction state', async () => {
  const first = fixture()
  const second = fixture({ rows: [] })
  let calls = 0
  const repository = createUserSearchRuntimeRepository({
    async connect() {
      calls += 1
      return calls === 1 ? first.client : second.client
    },
  })
  assert.deepEqual(
    await Promise.all([repository.searchUsers(INPUT), repository.searchUsers(INPUT)]),
    [[ROW], []],
  )
  assert.equal(calls, 2)
  assert.deepEqual(first.releases, [false])
  assert.deepEqual(second.releases, [false])
})

test('requires a connection pool dependency', () => {
  for (const pool of [undefined, null, {}, { connect: true }]) {
    assert.throws(() => createUserSearchRuntimeRepository(pool), TypeError)
  }
})
