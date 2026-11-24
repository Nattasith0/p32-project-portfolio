import test from 'node:test'
import assert from 'node:assert/strict'
import { createAuthorizationRepository } from '../src/modules/authorization/authorization.repository.js'

test('uses a SQL parameter for the user identifier', async () => {
  const userId = "' OR 1=1 --"
  const repository = createAuthorizationRepository({
    async query(sql, values) {
      assert.match(sql, /WHERE ur\.user_id = \$1/)
      assert.equal(sql.includes(userId), false)
      assert.deepEqual(values, [userId])

      return { rows: [] }
    },
  })

  assert.deepEqual(await repository.findRoleCodesByUserId(userId), [])
})

test('returns multiple role codes without unrelated row fields', async () => {
  const repository = createAuthorizationRepository({
    async query(sql) {
      assert.match(sql, /ORDER BY ur\.role_code/)

      return {
        rows: [
          { role_code: 'advisor', role_name: 'TEST_ONLY_NAME' },
          { role_code: 'examiner', assigned_by: 'TEST_ONLY_ASSIGNER' },
        ],
      }
    },
  })

  assert.deepEqual(await repository.findRoleCodesByUserId('test-user'), [
    'advisor',
    'examiner',
  ])
})

test('returns an empty list when the query finds no eligible roles', async () => {
  const repository = createAuthorizationRepository({
    query: async () => ({ rows: [] }),
  })

  assert.deepEqual(await repository.findRoleCodesByUserId('missing-user'), [])
})

test('requires active and email-verified accounts in the SQL query', async () => {
  const repository = createAuthorizationRepository({
    async query(sql) {
      assert.match(sql, /JOIN p32\.users AS u ON u\.user_id = ur\.user_id/)
      assert.match(sql, /u\.is_active = TRUE/)
      assert.match(sql, /u\.email_verified_at IS NOT NULL/)

      return { rows: [] }
    },
  })

  await repository.findRoleCodesByUserId('test-user')
})

test('queries again so a previous role result is not cached', async () => {
  let count = 0

  const repository = createAuthorizationRepository({
    async query() {
      count += 1

      return {
        rows: count === 1 ? [{ role_code: 'student' }] : [],
      }
    },
  })

  assert.deepEqual(await repository.findRoleCodesByUserId('test-user'), [
    'student',
  ])
  assert.deepEqual(await repository.findRoleCodesByUserId('test-user'), [])
  assert.equal(count, 2)
})

test('propagates a database failure instead of treating it as no roles', async () => {
  const failure = new Error('TEST_ONLY_DATABASE_FAILURE')

  const repository = createAuthorizationRepository({
    query: async () => {
      throw failure
    },
  })

  await assert.rejects(
    repository.findRoleCodesByUserId('test-user'),
    (error) => error === failure,
  )
})

test('requires a database query executor', () => {
  for (const database of [undefined, null, {}, { query: 123 }]) {
    assert.throws(() => createAuthorizationRepository(database), TypeError)
  }
})