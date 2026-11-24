import test from 'node:test'
import assert from 'node:assert/strict'
import { createRoleChangeRepository } from '../src/modules/roles/role-change.repository.js'

const input = Object.freeze({
  actorUserId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  targetUserId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  roleCode: 'advisor',
  action: 'assign',
  reason: 'แต่งตั้งอาจารย์ที่ปรึกษา',
  requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
})
const auditId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'

test('uses one parameterized function call and preserves all six input values', async () => {
  let calls = 0
  const request = { ...input, reason: "เหตุผลทดสอบ '; DROP TABLE p32.users; --" }
  const database = {
    async query(sql, values) {
      calls += 1
      assert.equal(this, database)
      assert.match(sql, /SELECT changed, audit_id/)
      assert.match(sql, /FROM p32\.change_user_role\s*\(/)
      assert.match(sql, /\$1::uuid, \$2::uuid, \$3::text/)
      assert.match(sql, /\$4::text, \$5::text, \$6::uuid/)
      assert.equal(sql.includes(request.reason), false)
      assert.doesNotMatch(sql, /SELECT\s+\*|INSERT\s+INTO|DELETE\s+FROM/i)
      assert.deepEqual(values, [
        request.actorUserId, request.targetUserId, request.roleCode,
        request.action, request.reason, request.requestId,
      ])
      return { rows: [{ changed: true, audit_id: auditId }] }
    },
  }
  const result = await createRoleChangeRepository(database).changeUserRole(request)
  assert.deepEqual(result, { changed: true, auditId })
  assert.equal(calls, 1)
})

test('maps a no-op result to false and null', async () => {
  const repository = createRoleChangeRepository({
    query: async () => ({ rows: [{ changed: false, audit_id: null }] }),
  })
  assert.deepEqual(await repository.changeUserRole(input), { changed: false, auditId: null })
})

test('projects only allowed fields without changing the database row', async () => {
  const row = Object.freeze({
    changed: true, audit_id: auditId, private_note: 'TEST_ONLY_PRIVATE',
  })
  const repository = createRoleChangeRepository({ query: async () => ({ rows: [row] }) })
  const result = await repository.changeUserRole(input)
  assert.deepEqual(result, { changed: true, auditId })
  assert.equal(row.private_note, 'TEST_ONLY_PRIVATE')
  assert.notEqual(result, row)
})

test('rejects missing, malformed and multiple result rows', async () => {
  for (const result of [
    undefined, null, {}, { rows: null }, { rows: 'invalid' }, { rows: [] },
    { rows: [undefined] }, { rows: [null] }, { rows: [[]] },
    { rows: [{ changed: false, audit_id: null }, { changed: false, audit_id: null }] },
  ]) {
    const repository = createRoleChangeRepository({ query: async () => result })
    await assert.rejects(repository.changeUserRole(input), /Invalid role change result/)
  }
})

test('requires a boolean and an audit UUID exactly when changed is true', async () => {
  for (const row of [
    {}, { changed: 'true', audit_id: auditId }, { changed: 1, audit_id: auditId },
    { changed: true, audit_id: null }, { changed: true, audit_id: 'invalid' },
    { changed: true, audit_id: auditId + '\n' }, { changed: true, audit_id: 123 },
    { changed: false, audit_id: auditId }, { changed: false },
  ]) {
    const repository = createRoleChangeRepository({ query: async () => ({ rows: [row] }) })
    await assert.rejects(repository.changeUserRole(input), /Invalid role change result/)
  }
})

test('propagates every role-change database error without retrying or returning no-op', async () => {
  for (const code of ['P3201','P3202','P3203','P3204','P3205','P3206','P3207','23514','57014','ECONNRESET']) {
    const failure = Object.assign(new Error('TEST_ONLY_DATABASE_FAILURE'), { code })
    let calls = 0
    const repository = createRoleChangeRepository({
      async query() { calls += 1; throw failure },
    })
    await assert.rejects(repository.changeUserRole(input), (error) => error === failure)
    assert.equal(calls, 1)
  }
})

test('captures input values before awaiting the query and leaves its input untouched', async () => {
  const request = { ...input }
  let received
  let finish
  const repository = createRoleChangeRepository({
    query(sql, values) {
      received = values
      return new Promise((resolve) => { finish = resolve })
    },
  })
  const pending = repository.changeUserRole(request)
  assert.deepEqual(request, input)
  request.reason = 'เปลี่ยนค่าฝั่งผู้เรียกขณะรอ'
  assert.equal(received[4], input.reason)
  finish({ rows: [{ changed: true, audit_id: auditId }] })
  assert.deepEqual(await pending, { changed: true, auditId })
})

test('requires a database query executor', () => {
  for (const database of [undefined, null, {}, { query: null }, { query: 123 }]) {
    assert.throws(() => createRoleChangeRepository(database), TypeError)
  }
})
