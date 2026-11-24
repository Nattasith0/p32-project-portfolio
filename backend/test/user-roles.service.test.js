import assert from 'node:assert/strict'
import test from 'node:test'
import {
  createUserRolesService,
  UserRolesError,
} from '../src/modules/users/user-roles.service.js'

const ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const ACCOUNT = Object.freeze({
  user_id: ID,
  username: 'faculty_demo',
  display_name: 'อาจารย์ทดสอบ',
  is_active: true,
  email_verified: true,
})
const ADVISOR = Object.freeze({
  ...ACCOUNT,
  role_code: 'advisor',
  role_name: 'อาจารย์ที่ปรึกษา',
})
const MANAGER = Object.freeze({
  ...ACCOUNT,
  role_code: 'course_manager',
  role_name: 'ผู้ดูแลวิชา',
})
const NO_ROLE = Object.freeze({ ...ACCOUNT, role_code: null, role_name: null })

function withRows(rows) {
  return createUserRolesService({
    userRolesRepository: { findUserRolesByUserId: async () => rows },
  })
}

test('normalizes the target and projects only the account and role fields in query order', async () => {
  const rows = Object.freeze([
    Object.freeze({
      ...ADVISOR,
      email: 'private@example.test',
      assigned_by: 'internal',
    }),
    MANAGER,
  ])
  const service = createUserRolesService({
    userRolesRepository: {
      async findUserRolesByUserId(target) {
        assert.equal(target, ID)
        return rows
      },
    },
  })

  assert.deepEqual(await service.getUserRoles(ID.toUpperCase()), {
    user: {
      userId: ID,
      username: 'faculty_demo',
      displayName: 'อาจารย์ทดสอบ',
      isActive: true,
      emailVerified: true,
    },
    roles: [
      { roleCode: 'advisor', roleName: 'อาจารย์ที่ปรึกษา' },
      { roleCode: 'course_manager', roleName: 'ผู้ดูแลวิชา' },
    ],
  })
})

test('distinguishes an existing account without roles from a missing account', async () => {
  const result = await withRows([NO_ROLE]).getUserRoles(ID)
  assert.equal(result.user.userId, ID)
  assert.deepEqual(result.roles, [])
  await assert.rejects(
    withRows([]).getUserRoles(ID),
    (error) => error instanceof UserRolesError && error.code === 'USER_NOT_FOUND',
  )
})

test('keeps existing roles visible for an inactive and unverified account', async () => {
  const result = await withRows([
    { ...ADVISOR, is_active: false, email_verified: false },
  ]).getUserRoles(ID)
  assert.equal(result.user.isActive, false)
  assert.equal(result.user.emailVerified, false)
  assert.deepEqual(result.roles, [
    { roleCode: 'advisor', roleName: 'อาจารย์ที่ปรึกษา' },
  ])
})

test('rejects invalid input before consulting the repository', async () => {
  const service = createUserRolesService({
    userRolesRepository: {
      async findUserRolesByUserId() {
        assert.fail('Unexpected lookup')
      },
    },
  })
  for (const input of [null, { userId: ID }, 'invalid', `${ID}\n`]) {
    await assert.rejects(
      service.getUserRoles(input),
      (error) =>
        error instanceof UserRolesError && error.code === 'INVALID_USER_ROLES_INPUT',
    )
  }
})

test('rejects malformed results and rows that describe a different or inconsistent account', async () => {
  for (const rows of [
    null,
    {},
    [null],
    Array(1),
    [{ ...ADVISOR, user_id: '00000000-0000-0000-0000-000000000000' }],
    [{ ...ADVISOR, display_name: ' ' }],
    [{ ...ADVISOR, is_active: 'true' }],
    [{ ...ADVISOR, email_verified: false }],
    [ADVISOR, { ...MANAGER, username: 'other' }],
    [ADVISOR, { ...MANAGER, is_active: false }],
  ]) {
    await assert.rejects(withRows(rows).getUserRoles(ID), TypeError)
  }
})

test('rejects duplicate roles and contradictory null or malformed assignments', async () => {
  for (const rows of [
    [ADVISOR, ADVISOR],
    [NO_ROLE, ADVISOR],
    [NO_ROLE, NO_ROLE],
    [{ ...ADVISOR, role_name: null }],
    [{ ...ADVISOR, role_name: ' ' }],
    [{ ...ADVISOR, role_code: null }],
    [{ ...ADVISOR, role_code: 'advisor\n' }],
  ]) {
    await assert.rejects(withRows(rows).getUserRoles(ID), TypeError)
  }
})

test('propagates database failures without retry or mapping them to a missing account', async () => {
  const failure = new Error('TEST_ONLY_DATABASE_FAILURE')
  let calls = 0
  const service = createUserRolesService({
    userRolesRepository: {
      async findUserRolesByUserId() {
        calls += 1
        throw failure
      },
    },
  })
  await assert.rejects(service.getUserRoles(ID), (error) => error === failure)
  assert.equal(calls, 1)
})
