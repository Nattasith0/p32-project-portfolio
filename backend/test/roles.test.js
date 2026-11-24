import test from 'node:test'
import assert from 'node:assert/strict'
import { createRoleRepository } from '../src/modules/roles/roles.repository.js'
import { createRoleService } from '../src/modules/roles/roles.service.js'

test('reads ordered role metadata and maps only the public fields', async () => {
  let queries = 0
  const repository = createRoleRepository({
    async query(sql) {
      queries += 1
      assert.match(sql, /SELECT role_code, role_name/)
      assert.match(sql, /FROM p32\.roles/)
      assert.match(sql, /ORDER BY role_code/)
      assert.doesNotMatch(sql, /SELECT\s+\*/i)
      return {
        rows: [
          { role_code: 'advisor', role_name: 'อาจารย์ที่ปรึกษา', private_field: 'TEST_ONLY_PRIVATE' },
          { role_code: 'student', role_name: 'นักศึกษาในโครงงาน' },
        ],
      }
    },
  })
  const service = createRoleService({ roleRepository: repository })
  assert.deepEqual(await service.listRoles(), [
    { roleCode: 'advisor', roleName: 'อาจารย์ที่ปรึกษา' },
    { roleCode: 'student', roleName: 'นักศึกษาในโครงงาน' },
  ])
  assert.equal(queries, 1)
})

test('returns an empty catalog when no roles exist', async () => {
  const repository = createRoleRepository({ query: async () => ({ rows: [] }) })
  assert.deepEqual(await createRoleService({ roleRepository: repository }).listRoles(), [])
})

test('propagates query failures instead of returning an empty catalog', async () => {
  const failure = new Error('TEST_ONLY_QUERY_FAILURE')
  const repository = createRoleRepository({ query: async () => { throw failure } })
  const service = createRoleService({ roleRepository: repository })
  await assert.rejects(service.listRoles(), (error) => error === failure)
})

test('does not mutate repository rows and reads again on each call', async () => {
  const row = Object.freeze({ role_code: 'student', role_name: 'นักศึกษาในโครงงาน' })
  let calls = 0
  const service = createRoleService({
    roleRepository: {
      async findAllRoles() {
        calls += 1
        return calls === 1 ? Object.freeze([row]) : []
      },
    },
  })
  assert.deepEqual(await service.listRoles(), [{ roleCode: 'student', roleName: row.role_name }])
  assert.deepEqual(await service.listRoles(), [])
  assert.equal(calls, 2)
})

test('rejects malformed catalog results', async () => {
  for (const rows of [undefined, null, true, {}, 'student']) {
    const service = createRoleService({ roleRepository: { findAllRoles: async () => rows } })
    await assert.rejects(service.listRoles(), TypeError)
  }
})

test('rejects malformed rows instead of silently returning a partial catalog', async () => {
  const valid = { role_code: 'student', role_name: 'นักศึกษาในโครงงาน' }
  const invalidRows = [
    undefined, null, {},
    { ...valid, role_code: 1 },
    { ...valid, role_code: '' },
    { ...valid, role_code: 'Student' },
    { ...valid, role_code: 'student\n' },
    { ...valid, role_code: 'student OR 1=1' },
    { ...valid, role_name: null },
    { ...valid, role_name: '   ' },
  ]
  for (const row of invalidRows) {
    const service = createRoleService({ roleRepository: { findAllRoles: async () => [valid, row] } })
    await assert.rejects(service.listRoles(), TypeError)
  }
})

test('requires a database query executor', () => {
  for (const database of [undefined, null, {}, { query: true }]) {
    assert.throws(() => createRoleRepository(database), TypeError)
  }
})

test('requires a repository with a catalog lookup function', () => {
  assert.throws(() => createRoleService(), TypeError)
  for (const roleRepository of [null, {}, { findAllRoles: true }]) {
    assert.throws(() => createRoleService({ roleRepository }), TypeError)
  }
})
