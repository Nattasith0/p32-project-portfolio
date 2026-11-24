import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'
import { createRoleChangeRepository } from '../src/modules/roles/role-change.repository.js'
import { checkRoleChangeDatabase } from './checks/role-change-database.checks.js'

export async function checkRoleChangeRepository(client, onStep = () => {}) {
  return checkRoleChangeDatabase(client, {
    createOperation: (database) => createRoleChangeRepository(database).changeUserRole,
    forbiddenCode: 'P3202',
    onStep,
  })
}

async function main() {
  let pool
  let client
  let checkName = 'development settings'

  try {
    assert.equal(process.env.NODE_ENV, 'development')
    assert.ok(['127.0.0.1', 'localhost', '::1'].includes(process.env.PGHOST))
    assert.equal(process.env.PGUSER, 'p32_app')
    assert.equal(process.env.PGDATABASE, 'p32_dev')

    checkName = 'database connection'
    const databaseModule = await import('../src/database/pool.js')
    pool = databaseModule.pool
    client = await pool.connect()
    await checkRoleChangeRepository(client, (name) => {
      checkName = name
    })

    console.log('Role change repository database checks passed; test data rolled back.')
  } catch (error) {
    console.error(
      `Role change repository check failed: ${checkName} (${error.code ?? 'CHECK_FAILED'})`,
    )
    process.exitCode = 1
  } finally {
    // ทำลาย client เฉพาะนี้ เพื่อไม่ส่งต่อ session settings หรือ transaction ที่ผิดพลาด
    if (client) client.release(true)
    if (pool) await pool.end()
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main()
}
