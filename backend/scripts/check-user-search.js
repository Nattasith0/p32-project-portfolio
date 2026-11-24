import assert from 'node:assert/strict'
import { checkUserSearchDatabase } from './checks/user-search-database.checks.js'

let pool
let client
let transactionStarted = false
let clientFailure
let checkName = 'database settings'

try {
  assert.ok(['127.0.0.1', 'localhost', '::1'].includes(process.env.PGHOST))
  assert.equal(process.env.PGUSER, 'p32_app')
  assert.equal(process.env.PGDATABASE, 'p32_dev')

  // โหลด pool หลังผ่านการตรวจค่าปลายทาง จึงไม่ติดต่อฐานอื่นเมื่อ config ผิด
  const databaseModule = await import('../src/database/pool.js')
  pool = databaseModule.pool
  checkName = 'database connection'
  client = await pool.connect()
  client.on('error', (error) => {
    clientFailure = error
  })

  const database = {
    async query(text, values) {
      if (clientFailure) throw clientFailure
      const result = await client.query({ text, values, query_timeout: 10000 })
      if (clientFailure) throw clientFailure
      return result
    },
  }

  checkName = 'read-only transaction setup'
  await database.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
  transactionStarted = true
  await database.query("SET LOCAL statement_timeout = '5s'")
  await database.query("SET LOCAL lock_timeout = '2s'")
  await database.query("SET LOCAL idle_in_transaction_session_timeout = '15s'")

  await checkUserSearchDatabase(database, (name) => {
    checkName = name
  })

  checkName = 'read-only transaction cleanup'
  await database.query('ROLLBACK')
  transactionStarted = false
  console.log('User search database checks passed; read-only transaction rolled back.')
} catch {
  // ไม่แสดง query, input, assertion details หรือข้อมูลบัญชีจาก error
  console.error(`User search database check failed: ${checkName}`)
  process.exitCode = 1
} finally {
  if (client) {
    try {
      if (transactionStarted) {
        await client.query({ text: 'ROLLBACK', query_timeout: 10000 })
      }
    } catch {
      console.error('User search database check cleanup failed')
      process.exitCode = 1
    } finally {
      // ตัวตรวจใช้ connection ครั้งเดียว ปิดทิ้งรวมถึงกรณี state ไม่แน่นอน
      client.release(true)
    }
  }
  if (pool) await pool.end()
}
