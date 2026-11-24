import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { pool } from '../src/database/pool.js'
import { createAuthorizationRepository } from '../src/modules/authorization/authorization.repository.js'

let client
let transactionStarted = false
let checkName = 'database settings'

try {
  assert.ok(['127.0.0.1', 'localhost', '::1'].includes(process.env.PGHOST))
  assert.equal(process.env.PGUSER, 'p32_app')
  assert.equal(process.env.PGDATABASE, 'p32_dev')

  checkName = 'database connection'
  client = await pool.connect()

  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
  transactionStarted = true

  checkName = 'database target and read-only transaction'

  const target = await client.query(`
    SELECT
      current_user AS db_user,
      current_database() AS db_name,
      current_setting('is_superuser')::boolean AS is_superuser,
      current_setting('transaction_read_only')::boolean AS read_only,
      host(inet_server_addr()) AS server_address
  `)

  const database = target.rows[0]

  assert.equal(database.db_user, 'p32_app')
  assert.equal(database.db_name, 'p32_dev')
  assert.equal(database.is_superuser, false)
  assert.equal(database.read_only, true)
  assert.ok(['127.0.0.1', '::1'].includes(database.server_address))

  checkName = 'demo accounts and roles'

  const users = await client.query(`
    SELECT user_id, username, is_active,
           email_verified_at IS NOT NULL AS email_verified
    FROM p32.users
    WHERE username IN ($1, $2)
  `, ['admin_demo', 'student_demo'])

  const repository = createAuthorizationRepository(client)

  for (const [username, expectedRole] of [
    ['admin_demo', 'system_admin'],
    ['student_demo', 'student'],
  ]) {
    const user = users.rows.find((row) => row.username === username)

    assert.ok(user)
    assert.equal(user.is_active, true)
    assert.equal(user.email_verified, true)

    assert.deepEqual(
      await repository.findRoleCodesByUserId(user.user_id),
      [expectedRole],
    )
  }

  checkName = 'missing account'

  const missingId = randomUUID()
  const existing = await client.query(
    'SELECT 1 FROM p32.users WHERE user_id = $1',
    [missingId],
  )

  assert.equal(existing.rows.length, 0)
  assert.deepEqual(await repository.findRoleCodesByUserId(missingId), [])

  checkName = 'invalid identifier stays a SQL parameter'

  await client.query('SAVEPOINT before_invalid_id')

  await assert.rejects(
    repository.findRoleCodesByUserId("' OR 1=1 --"),
    (error) => error.code === '22P02',
  )

  await client.query('ROLLBACK TO SAVEPOINT before_invalid_id')

  checkName = 'transaction cleanup'

  await client.query('ROLLBACK')
  transactionStarted = false

  console.log(
    'Authorization repository database checks passed; read-only transaction rolled back.',
  )
} catch {
  console.error(`Authorization repository check failed: ${checkName}`)
  process.exitCode = 1
} finally {
  if (client) {
    try {
      if (transactionStarted) await client.query('ROLLBACK')
    } catch {
      console.error('Authorization repository check cleanup failed')
      process.exitCode = 1
    } finally {
      client.release()
    }
  }

  await pool.end()
}