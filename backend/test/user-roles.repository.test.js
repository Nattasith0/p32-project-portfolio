import test from 'node:test'
import assert from 'node:assert/strict'
import { createUserRolesRepository } from '../src/modules/users/user-roles.repository.js'

const ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const user = {
  user_id: ID,
  username: 'faculty_demo',
  display_name: 'อาจารย์ทดสอบ',
  is_active: true,
  email_verified: true,
}

test('uses one parameterized lookup with explicit minimal columns and ordered LEFT JOINs', async () => {
  let calls = 0
  const repository = createUserRolesRepository({
    async query(sql, values) {
      calls += 1
      assert.deepEqual(values, [ID])
      assert.match(sql, /WHERE u\.user_id = \$1::uuid/)
      assert.match(sql, /LEFT JOIN p32\.user_roles AS ur ON ur\.user_id = u\.user_id/)
      assert.match(sql, /LEFT JOIN p32\.roles AS r ON r\.role_code = ur\.role_code/)
      assert.match(sql, /ORDER BY ur\.role_code ASC/)
      assert.doesNotMatch(sql, /SELECT\s+\*|password|token|assigned_by|assigned_at/i)
      assert.doesNotMatch(sql, /u\.email\b/)
      assert.ok(!sql.includes(ID))
      return {
        rows: [{ ...user, role_code: 'advisor', role_name: 'อาจารย์ที่ปรึกษา' }],
      }
    },
  })
  assert.deepEqual(await repository.findUserRolesByUserId(ID.toUpperCase()), [
    { ...user, role_code: 'advisor', role_name: 'อาจารย์ที่ปรึกษา' },
  ])
  assert.equal(calls, 1)
})

test('does not hide inactive or unverified targets behind authorization-style filters', async () => {
  const row = {
    ...user,
    is_active: false,
    email_verified: false,
    role_code: 'advisor',
    role_name: 'อาจารย์ที่ปรึกษา',
  }
  const repository = createUserRolesRepository({
    async query(sql) {
      assert.doesNotMatch(
        sql,
        /(?:WHERE|AND)\s+(?:u\.)?(?:is_active|email_verified_at)/i,
      )
      return { rows: [row] }
    },
  })
  assert.deepEqual(await repository.findUserRolesByUserId(ID), [row])
})

test('distinguishes a missing account from an existing account without roles', async () => {
  const row = { ...user, role_code: null, role_name: null }
  let calls = 0
  const repository = createUserRolesRepository({
    async query() {
      calls += 1
      return { rows: calls === 1 ? [] : [row] }
    },
  })
  assert.deepEqual(await repository.findUserRolesByUserId(ID), [])
  assert.deepEqual(await repository.findUserRolesByUserId(ID), [row])
  assert.equal(calls, 2)
})

test('preserves all assigned roles for a multi-role account without mutating rows', async () => {
  const rows = Object.freeze([
    Object.freeze({ ...user, role_code: 'advisor', role_name: 'อาจารย์ที่ปรึกษา' }),
    Object.freeze({ ...user, role_code: 'course_manager', role_name: 'ผู้ดูแลวิชา' }),
  ])
  const repository = createUserRolesRepository({ query: async () => ({ rows }) })
  assert.deepEqual(await repository.findUserRolesByUserId(ID), rows)
})

test('rejects invalid target identifiers before any database query', async () => {
  let calls = 0
  const repository = createUserRolesRepository({
    async query() {
      calls += 1
      return { rows: [] }
    },
  })
  for (const value of [
    undefined,
    null,
    [],
    { userId: ID },
    '',
    ID + '\n',
    "x' OR 1=1 --",
  ]) {
    await assert.rejects(repository.findUserRolesByUserId(value), TypeError)
  }
  assert.equal(calls, 0)
})

test('propagates database failures without retry or converting failure into a missing account', async () => {
  const failure = new Error('TEST_ONLY_DATABASE_FAILURE')
  let calls = 0
  const repository = createUserRolesRepository({
    async query() {
      calls += 1
      throw failure
    },
  })
  await assert.rejects(
    repository.findUserRolesByUserId(ID),
    (error) => error === failure,
  )
  assert.equal(calls, 1)
})

test('rejects malformed database response containers', async () => {
  for (const result of [
    undefined,
    null,
    {},
    { rows: null },
    { rows: {} },
    { rows: 'invalid' },
  ]) {
    const repository = createUserRolesRepository({ query: async () => result })
    await assert.rejects(repository.findUserRolesByUserId(ID), TypeError)
  }
})

test('requires a database query executor', () => {
  for (const database of [undefined, null, {}, { query: true }]) {
    assert.throws(() => createUserRolesRepository(database), TypeError)
  }
})
