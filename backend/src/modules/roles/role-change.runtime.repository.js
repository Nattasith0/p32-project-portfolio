import { createRoleChangeRepository } from './role-change.repository.js'

export function createRoleChangeRuntimeRepository(pool) {
  if (typeof pool?.connect !== 'function') {
    throw new TypeError('A database pool is required')
  }

  async function changeUserRole(change) {
    // ใช้ connection เดียวสำหรับ BEGIN, ค่าตั้ง, mutation และ COMMIT/ROLLBACK
    const client = await pool.connect()
    let committed = false
    let connectionError = null
    const onConnectionError = (error) => {
      connectionError ??= error
    }
    client.on('error', onConnectionError)

    const query = (text, values) => {
      if (connectionError) throw connectionError
      return client.query({ text, values, query_timeout: 10000 })
    }

    try {
      await query('BEGIN ISOLATION LEVEL READ COMMITTED')
      await query("SET LOCAL statement_timeout = '5s'")
      await query("SET LOCAL lock_timeout = '2s'")
      await query("SET LOCAL idle_in_transaction_session_timeout = '15s'")

      const repository = createRoleChangeRepository({ query })
      const result = await repository.changeUserRole(change)

      const completion = await query('COMMIT')
      if (completion?.command !== 'COMMIT') {
        throw new TypeError('Role change transaction did not confirm COMMIT')
      }
      committed = true
      return result
    } catch (error) {
      try {
        await query('ROLLBACK')
      } catch {
        // คง error เดิม; connection ที่ล้มเหลวจะถูกทิ้ง ไม่ส่งกลับไปใช้งานต่อ
      }
      // ถ้าการเชื่อมต่อขาดระหว่าง COMMIT ยังสรุปไม่ได้ว่าข้อมูลเปลี่ยนหรือไม่
      throw error
    } finally {
      const discard = !committed || connectionError !== null
      client.release(discard)
      // เมื่อทิ้ง client คง listener ไว้รองรับ error ระหว่างปิด connection
      if (!discard) client.removeListener('error', onConnectionError)
    }
  }

  return { changeUserRole }
}
