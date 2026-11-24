import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { createRoleChangeRuntimeRepository } from '../src/modules/roles/role-change.runtime.repository.js'

const INPUT = Object.freeze({
  actorUserId: '00000000-0000-4000-8000-000000000001',
  targetUserId: '00000000-0000-4000-8000-000000000002',
  roleCode: 'advisor',
  action: 'assign',
  reason: 'มอบหมายหน้าที่',
  requestId: '00000000-0000-4000-8000-000000000401',
})
const AUDIT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

function fixture({
  row = { changed: true, audit_id: AUDIT },
  failAt,
  failure,
  rollbackFailure,
  commitResult,
  waitForCommit,
} = {}) {
  const calls = []
  const releases = []
  let acquired = 0
  const client = new EventEmitter()
  client.query = async (config) => {
    calls.push(config)
    if (
      config.text === failAt ||
      (failAt === 'mutation' && config.text.includes('FROM p32.change_user_role'))
    ) {
      throw failure
    }
    if (config.text === 'ROLLBACK' && rollbackFailure) throw rollbackFailure
    if (config.text.includes('FROM p32.change_user_role')) return { rows: [row] }
    if (config.text === 'COMMIT') {
      if (waitForCommit) await waitForCommit
      return commitResult ?? { command: 'COMMIT' }
    }
    return { rows: [] }
  }
  client.release = (discard) => {
    releases.push(discard)
  }
  const pool = {
    async connect() {
      acquired += 1
      return client
    },
    query() {
      assert.fail('must not use pool.query for this transaction')
    },
  }
  return { client, pool, calls, releases, acquired: () => acquired }
}

test('uses one client with local limits, validates the result and confirms COMMIT before release', async () => {
  const state = fixture()
  const repository = createRoleChangeRuntimeRepository(state.pool)
  assert.deepEqual(await repository.changeUserRole(INPUT), {
    changed: true,
    auditId: AUDIT,
  })
  const texts = state.calls.map((call) => call.text)
  assert.deepEqual(texts.slice(0, 4), [
    'BEGIN ISOLATION LEVEL READ COMMITTED',
    "SET LOCAL statement_timeout = '5s'",
    "SET LOCAL lock_timeout = '2s'",
    "SET LOCAL idle_in_transaction_session_timeout = '15s'",
  ])
  assert.match(texts[4], /FROM p32\.change_user_role/)
  assert.deepEqual(state.calls[4].values, [
    INPUT.actorUserId,
    INPUT.targetUserId,
    INPUT.roleCode,
    INPUT.action,
    INPUT.reason,
    INPUT.requestId,
  ])
  assert.equal(texts[5], 'COMMIT')
  assert.equal(texts.length, 6)
  assert.ok(state.calls.every((call) => call.query_timeout === 10000))
  assert.deepEqual(state.releases, [false])
  assert.equal(state.acquired(), 1)
  assert.equal(state.client.listenerCount('error'), 0)
})

test('commits a verified no-op and returns false/null without retry', async () => {
  const state = fixture({ row: { changed: false, audit_id: null } })
  assert.deepEqual(
    await createRoleChangeRuntimeRepository(state.pool).changeUserRole(INPUT),
    { changed: false, auditId: null },
  )
  assert.equal(
    state.calls.filter((call) => call.text.includes('FROM p32.change_user_role')).length,
    1,
  )
  assert.equal(state.calls.at(-1).text, 'COMMIT')
})

test('does not resolve or release the connection before COMMIT is acknowledged', async () => {
  let finish
  const waiting = new Promise((resolve) => {
    finish = resolve
  })
  const state = fixture({ waitForCommit: waiting })
  let done = false
  const pending = createRoleChangeRuntimeRepository(state.pool)
    .changeUserRole(INPUT)
    .then(() => {
      done = true
    })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(state.calls.at(-1).text, 'COMMIT')
  assert.equal(done, false)
  assert.deepEqual(state.releases, [])
  finish()
  await pending
  assert.equal(done, true)
  assert.deepEqual(state.releases, [false])
})

for (const code of ['P3202', 'P3206', 'P3207', '55P03', '57014', 'ECONNRESET']) {
  test(`rolls back ${code}, discards the client and propagates the original failure once`, async () => {
    const failure = Object.assign(new Error('PRIVATE_DATABASE_FAILURE'), { code })
    const state = fixture({ failAt: 'mutation', failure })
    await assert.rejects(
      createRoleChangeRuntimeRepository(state.pool).changeUserRole(INPUT),
      (error) => error === failure,
    )
    assert.equal(state.calls.at(-1).text, 'ROLLBACK')
    assert.equal(
      state.calls.some((call) => call.text === 'COMMIT'),
      false,
    )
    assert.equal(
      state.calls.filter((call) => call.text.includes('FROM p32.change_user_role'))
        .length,
      1,
    )
    assert.deepEqual(state.releases, [true])
    assert.equal(state.acquired(), 1)
  })
}

test('preserves the initial error if rollback also fails', async () => {
  const failure = new Error('INITIAL_FAILURE')
  const state = fixture({
    failAt: 'mutation',
    failure,
    rollbackFailure: new Error('ROLLBACK_FAILURE'),
  })
  await assert.rejects(
    createRoleChangeRuntimeRepository(state.pool).changeUserRole(INPUT),
    (error) => error === failure,
  )
  assert.deepEqual(state.releases, [true])
})

test('rolls back invalid repository results before any COMMIT', async () => {
  for (const row of [
    { changed: true, audit_id: null },
    { changed: false, audit_id: AUDIT },
  ]) {
    const state = fixture({ row })
    await assert.rejects(
      createRoleChangeRuntimeRepository(state.pool).changeUserRole(INPUT),
      TypeError,
    )
    assert.equal(state.calls.at(-1).text, 'ROLLBACK')
    assert.equal(
      state.calls.some((call) => call.text === 'COMMIT'),
      false,
    )
    assert.deepEqual(state.releases, [true])
  }
})

test('stops before mutation when BEGIN or a local timeout setting fails', async () => {
  for (const failAt of [
    'BEGIN ISOLATION LEVEL READ COMMITTED',
    "SET LOCAL statement_timeout = '5s'",
    "SET LOCAL lock_timeout = '2s'",
    "SET LOCAL idle_in_transaction_session_timeout = '15s'",
  ]) {
    const failure = new Error('SETUP_FAILURE')
    const state = fixture({ failAt, failure })
    await assert.rejects(
      createRoleChangeRuntimeRepository(state.pool).changeUserRole(INPUT),
      (error) => error === failure,
    )
    assert.equal(
      state.calls.some((call) => call.text.includes('FROM p32.change_user_role')),
      false,
    )
    assert.equal(state.calls.at(-1).text, 'ROLLBACK')
    assert.deepEqual(state.releases, [true])
  }
})

test('does not report success or retry if the COMMIT response is lost', async () => {
  const failure = Object.assign(new Error('COMMIT_ACK_LOST'), { code: 'ECONNRESET' })
  const state = fixture({ failAt: 'COMMIT', failure })
  await assert.rejects(
    createRoleChangeRuntimeRepository(state.pool).changeUserRole(INPUT),
    (error) => error === failure,
  )
  assert.equal(state.calls.filter((call) => call.text === 'COMMIT').length, 1)
  assert.equal(
    state.calls.filter((call) => call.text.includes('FROM p32.change_user_role')).length,
    1,
  )
  assert.equal(state.calls.at(-1).text, 'ROLLBACK')
  assert.deepEqual(state.releases, [true])
})

test('rejects a COMMIT response that does not confirm COMMIT', async () => {
  const state = fixture({ commitResult: { command: 'ROLLBACK' } })
  await assert.rejects(
    createRoleChangeRuntimeRepository(state.pool).changeUserRole(INPUT),
    TypeError,
  )
  assert.equal(state.calls.at(-1).text, 'ROLLBACK')
  assert.deepEqual(state.releases, [true])
})

test('propagates pool acquisition errors without retry or query', async () => {
  const failure = new Error('POOL_WAIT_TIMEOUT')
  let calls = 0
  const pool = {
    async connect() {
      calls += 1
      throw failure
    },
  }
  await assert.rejects(
    createRoleChangeRuntimeRepository(pool).changeUserRole(INPUT),
    (error) => error === failure,
  )
  assert.equal(calls, 1)
})

test('catches connection error events while the client is checked out and does not reuse it', async () => {
  const state = fixture()
  const failure = new Error('SOCKET_CLOSED')
  const original = state.client.query
  state.client.query = async (config) => {
    const result = await original(config)
    if (config.text.includes('FROM p32.change_user_role'))
      state.client.emit('error', failure)
    return result
  }
  await assert.rejects(
    createRoleChangeRuntimeRepository(state.pool).changeUserRole(INPUT),
    (error) => error === failure,
  )
  assert.equal(
    state.calls.some((call) => call.text === 'COMMIT'),
    false,
  )
  assert.deepEqual(state.releases, [true])
  // การปิด connection อาจมี error event ตามมา ต้องไม่กลายเป็น unhandled event
  assert.doesNotThrow(() => state.client.emit('error', new Error('CLOSING_CONNECTION')))
})

test('returns a committed result but discards a connection that fails after COMMIT acknowledgement', async () => {
  const state = fixture()
  const original = state.client.query
  state.client.query = async (config) => {
    const result = await original(config)
    if (config.text === 'COMMIT')
      state.client.emit('error', new Error('CLOSED_AFTER_COMMIT'))
    return result
  }
  assert.deepEqual(
    await createRoleChangeRuntimeRepository(state.pool).changeUserRole(INPUT),
    { changed: true, auditId: AUDIT },
  )
  assert.deepEqual(state.releases, [true])
})

test('checks out independent clients for concurrent operations', async () => {
  const a = fixture()
  const b = fixture({ row: { changed: false, audit_id: null } })
  const clients = [a.client, b.client]
  const repository = createRoleChangeRuntimeRepository({
    async connect() {
      return clients.shift()
    },
  })
  const results = await Promise.all([
    repository.changeUserRole(INPUT),
    repository.changeUserRole(INPUT),
  ])
  assert.deepEqual(results, [
    { changed: true, auditId: AUDIT },
    { changed: false, auditId: null },
  ])
  assert.deepEqual(a.releases, [false])
  assert.deepEqual(b.releases, [false])
  assert.equal(a.calls.at(-1).text, 'COMMIT')
  assert.equal(b.calls.at(-1).text, 'COMMIT')
})

test('requires a pool with a connect method', () => {
  for (const pool of [undefined, null, {}, { connect: true }]) {
    assert.throws(() => createRoleChangeRuntimeRepository(pool), TypeError)
  }
})
