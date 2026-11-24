import test from 'node:test'
import assert from 'node:assert/strict'
import {
  parseRoleChangeInput,
  parseRoleChangeUuid,
} from '../src/modules/roles/role-change.validation.js'

const input = Object.freeze({
  targetUserId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  roleCode: 'advisor',
  action: 'assign',
  reason: 'แต่งตั้งที่ปรึกษา',
})

test('normalizes UUID and trims reason without mutating its input', () => {
  const request = Object.freeze({
    ...input,
    targetUserId: input.targetUserId.toUpperCase(),
    reason: ' \nแต่งตั้งที่ปรึกษา\t ',
  })
  assert.deepEqual(parseRoleChangeInput(request), input)
  assert.equal(request.reason, ' \nแต่งตั้งที่ปรึกษา\t ')
})

test('rejects bodies that are not objects', () => {
  for (const value of [undefined, null, [], true, 123, 'text'])
    assert.equal(parseRoleChangeInput(value), null)
})

test('requires exactly four own fields and rejects client-supplied server context', () => {
  for (const field of Object.keys(input)) {
    const value = { ...input }
    delete value[field]
    assert.equal(parseRoleChangeInput(value), null)
  }
  for (const extra of [
    { actorUserId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
    { requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' },
    { roles: ['system_admin'] },
    { allowedRoles: ['system_admin'] },
    { isAdmin: true },
  ])
    assert.equal(parseRoleChangeInput({ ...input, ...extra }), null)
  assert.equal(parseRoleChangeInput(Object.create(input)), null)
  const prototypeField = JSON.parse(
    JSON.stringify(input).slice(0, -1) + ',"__proto__":{"isAdmin":true}}',
  )
  assert.equal(parseRoleChangeInput(prototypeField), null)
})

test('checks UUID syntax exactly and normalizes only valid identifiers', () => {
  assert.equal(parseRoleChangeUuid(input.targetUserId.toUpperCase()), input.targetUserId)
  for (const value of [
    undefined,
    null,
    123,
    {},
    '',
    'not-a-uuid',
    input.targetUserId + '\n',
    ' ' + input.targetUserId,
  ]) {
    assert.equal(parseRoleChangeUuid(value), null)
    assert.equal(parseRoleChangeInput({ ...input, targetUserId: value }), null)
  }
})

test('accepts the six known role codes and two exact actions', () => {
  for (const roleCode of [
    'student',
    'advisor',
    'course_manager',
    'examiner',
    'portfolio_viewer',
    'system_admin',
  ]) {
    for (const action of ['assign', 'revoke'])
      assert.ok(parseRoleChangeInput({ ...input, roleCode, action }))
  }
  for (const roleCode of [null, [], 1, '', 'Advisor', 'advisor ', 'unknown_role'])
    assert.equal(parseRoleChangeInput({ ...input, roleCode }), null)
  for (const action of [null, [], 1, '', 'ASSIGN', 'assign ', 'delete'])
    assert.equal(parseRoleChangeInput({ ...input, action }), null)
})

test('enforces 1 to 500 Unicode code points after trimming reason', () => {
  for (const reason of ['ก', '😀', 'ก'.repeat(500), '😀'.repeat(500)]) {
    assert.equal(parseRoleChangeInput({ ...input, reason }).reason, reason)
  }
  for (const reason of [
    '',
    ' \t\n',
    '\u0085',
    '\uFEFF',
    'ก'.repeat(501),
    '😀'.repeat(501),
    null,
    123,
  ]) {
    assert.equal(parseRoleChangeInput({ ...input, reason }), null)
  }
})

test('rejects NUL and malformed UTF-16 before reaching PostgreSQL', () => {
  for (const reason of ['a\0b', '\ud800', '\udc00', 'x\ud800y']) {
    assert.equal(parseRoleChangeInput({ ...input, reason }), null)
  }
})

test('preserves quotes, SQL-looking text and internal line breaks as data', () => {
  const reason = "เหตุผล '; DROP TABLE p32.users; --\nบรรทัดสอง"
  assert.equal(parseRoleChangeInput({ ...input, reason }).reason, reason)
  assert.deepEqual(parseRoleChangeInput(Object.assign(Object.create(null), input)), input)
})
