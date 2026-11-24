import test from 'node:test'
import assert from 'node:assert/strict'
import {
  createRoleChangeService,
  RoleChangeError,
} from '../src/modules/roles/role-change.service.js'

const actorUserId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
const auditId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
const input = Object.freeze({
  targetUserId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  roleCode: 'advisor',
  action: 'assign',
  reason: 'แต่งตั้งที่ปรึกษา',
})
const context = { actorUserId, requestId, input }
const matchesCode = (code) => (error) =>
  error instanceof RoleChangeError && error.code === code

test('validates input and passes only normalized server context and payload to repository', async () => {
  let calls = 0
  const service = createRoleChangeService({
    roleChangeRepository: {
      async changeUserRole(value) {
        calls += 1
        assert.deepEqual(value, { actorUserId, requestId, ...input })
        return { changed: true, auditId }
      },
    },
  })
  const request = Object.freeze({
    actorUserId: actorUserId.toUpperCase(),
    requestId: requestId.toUpperCase(),
    input: Object.freeze({
      ...input,
      targetUserId: input.targetUserId.toUpperCase(),
      reason: ' แต่งตั้งที่ปรึกษา ',
    }),
  })
  assert.deepEqual(await service.changeUserRole(request), { changed: true, auditId })
  assert.equal(calls, 1)
  assert.equal(request.input.reason, ' แต่งตั้งที่ปรึกษา ')
})

test('returns a no-op without converting it into an error', async () => {
  const service = createRoleChangeService({
    roleChangeRepository: {
      changeUserRole: async () => ({ changed: false, auditId: null }),
    },
  })
  assert.deepEqual(await service.changeUserRole(context), {
    changed: false,
    auditId: null,
  })
})

test('rejects client-supplied actor, request ID and role claims before calling repository', async () => {
  const service = createRoleChangeService({
    roleChangeRepository: { changeUserRole: async () => assert.fail('Must not query') },
  })
  for (const extra of [
    { actorUserId },
    { requestId },
    { roles: ['system_admin'] },
    { isAdmin: true },
  ]) {
    await assert.rejects(
      service.changeUserRole({ ...context, input: { ...input, ...extra } }),
      matchesCode('INVALID_ROLE_CHANGE_INPUT'),
    )
  }
})

test('rejects invalid payloads before database access', async () => {
  const service = createRoleChangeService({
    roleChangeRepository: { changeUserRole: async () => assert.fail('Must not query') },
  })
  for (const body of [
    undefined,
    null,
    {},
    [],
    { ...input, action: 'delete' },
    { ...input, reason: '\0' },
  ]) {
    await assert.rejects(
      service.changeUserRole({ ...context, input: body }),
      matchesCode('INVALID_ROLE_CHANGE_INPUT'),
    )
  }
})

test('treats invalid server context as an internal error before database access', async () => {
  const service = createRoleChangeService({
    roleChangeRepository: { changeUserRole: async () => assert.fail('Must not query') },
  })
  for (const value of [
    undefined,
    null,
    {},
    { ...context, actorUserId: 'invalid' },
    { ...context, requestId: null },
    { ...context, actorUserId: actorUserId + '\n' },
  ]) {
    await assert.rejects(service.changeUserRole(value), TypeError)
  }
})

test('maps only known business SQLSTATEs and discards private database details', async () => {
  const errors = [
    ['P3202', 'FORBIDDEN'],
    ['P3203', 'ROLE_TARGET_NOT_FOUND'],
    ['P3204', 'ROLE_NOT_FOUND'],
    ['P3205', 'ROLE_TARGET_NOT_READY'],
    ['P3206', 'LAST_SYSTEM_ADMIN'],
    ['P3207', 'ROLE_CHANGE_BUSY'],
  ]
  for (const [sqlstate, code] of errors) {
    const failure = Object.assign(new Error('PRIVATE_TEST_SQL_MESSAGE'), {
      code: sqlstate,
      detail: 'PRIVATE_TEST_DATA',
      status: 418,
    })
    let calls = 0
    const service = createRoleChangeService({
      roleChangeRepository: {
        async changeUserRole() {
          calls += 1
          throw failure
        },
      },
    })
    await assert.rejects(service.changeUserRole(context), (error) => {
      assert.ok(matchesCode(code)(error))
      assert.equal(error.message, 'Role change request rejected')
      assert.equal(error.detail, undefined)
      assert.equal(error.status, undefined)
      assert.notEqual(error, failure)
      return true
    })
    assert.equal(calls, 1)
  }
})

test('propagates P3201, unknown SQLSTATEs and network failures without retrying', async () => {
  for (const failure of [
    Object.assign(new Error('TEST_WRONG_ISOLATION'), { code: 'P3201' }),
    Object.assign(new Error('TEST_DATABASE_FAILURE'), { code: 'XX000' }),
    Object.assign(new Error('TEST_CANCELLED_QUERY'), { code: '57014' }),
    Object.assign(new Error('TEST_CONNECTION_FAILURE'), { code: 'ECONNRESET' }),
    { code: 'P3202', message: 'not an Error instance' },
  ]) {
    let calls = 0
    const service = createRoleChangeService({
      roleChangeRepository: {
        async changeUserRole() {
          calls += 1
          throw failure
        },
      },
    })
    await assert.rejects(service.changeUserRole(context), (error) => error === failure)
    assert.equal(calls, 1)
  }
})

test('validates and projects result fields without changing repository data', async () => {
  const row = Object.freeze({
    changed: true,
    auditId: auditId.toUpperCase(),
    private_note: 'TEST_ONLY_PRIVATE',
  })
  const service = createRoleChangeService({
    roleChangeRepository: { changeUserRole: async () => row },
  })
  assert.deepEqual(await service.changeUserRole(context), { changed: true, auditId })
  assert.equal(row.auditId, auditId.toUpperCase())
  assert.equal(row.private_note, 'TEST_ONLY_PRIVATE')
})

test('rejects malformed repository results instead of returning success', async () => {
  for (const result of [
    undefined,
    null,
    [],
    {},
    { changed: 'true', auditId },
    { changed: true, auditId: null },
    { changed: true, auditId: 'invalid' },
    { changed: true, auditId: auditId + '\n' },
    { changed: false, auditId },
    { changed: false },
  ]) {
    const service = createRoleChangeService({
      roleChangeRepository: { changeUserRole: async () => result },
    })
    await assert.rejects(service.changeUserRole(context), TypeError)
  }
})

test('calls repository on every request and does not cache a successful change', async () => {
  let calls = 0
  const service = createRoleChangeService({
    roleChangeRepository: {
      async changeUserRole() {
        calls += 1
        return calls === 1
          ? { changed: true, auditId }
          : { changed: false, auditId: null }
      },
    },
  })
  assert.deepEqual(await service.changeUserRole(context), { changed: true, auditId })
  assert.deepEqual(await service.changeUserRole(context), {
    changed: false,
    auditId: null,
  })
  assert.equal(calls, 2)
})

test('snapshots input and server context before awaiting repository', async () => {
  let received
  let finish
  const service = createRoleChangeService({
    roleChangeRepository: {
      changeUserRole(value) {
        received = value
        return new Promise((resolve) => {
          finish = resolve
        })
      },
    },
  })
  const request = { ...context, input: { ...input } }
  const pending = service.changeUserRole(request)
  request.actorUserId = 'ffffffff-ffff-4fff-8fff-ffffffffffff'
  request.input.reason = 'เปลี่ยนค่าระหว่างรอ'
  assert.deepEqual(received, { actorUserId, requestId, ...input })
  finish({ changed: true, auditId })
  assert.deepEqual(await pending, { changed: true, auditId })
})

test('requires repository dependency and restricts domain error codes', () => {
  for (const config of [
    undefined,
    null,
    {},
    { roleChangeRepository: {} },
    { roleChangeRepository: { changeUserRole: 123 } },
  ]) {
    assert.throws(() => createRoleChangeService(config), TypeError)
  }
  for (const code of [undefined, null, 'PRIVATE_SQL_MESSAGE', 'INTERNAL_ERROR']) {
    assert.throws(() => new RoleChangeError(code), TypeError)
  }
  assert.ok(new RoleChangeError('INVALID_ROLE_CHANGE_INPUT') instanceof Error)
})
