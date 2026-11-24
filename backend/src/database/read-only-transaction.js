export function createReadOnlyTransaction(pool) {
  if (typeof pool?.connect !== 'function') {
    throw new TypeError('A database pool is required')
  }

  return async function runReadOnly(operation) {
    const client = await pool.connect()
    let finished = false
    let rollbackAttempted = false
    let connectionError = null
    const onConnectionError = (error) => {
      connectionError ??= error
    }
    client.on('error', onConnectionError)

    const query = async (text, values) => {
      if (connectionError) throw connectionError
      const result = await client.query({ text, values, query_timeout: 10000 })
      if (connectionError) throw connectionError
      return result
    }

    try {
      // READ ONLY และค่าตั้งทั้งหมดอยู่บน connection เดียวกัน เฉพาะการอ่านครั้งนี้
      await query('BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY')
      await query("SET LOCAL statement_timeout = '5s'")
      await query("SET LOCAL lock_timeout = '2s'")
      await query("SET LOCAL idle_in_transaction_session_timeout = '15s'")

      const result = await operation({ query })

      // งานอ่านไม่ต้องบันทึกอะไร จบ transaction และคืนค่าตั้งก่อนคืน connection
      rollbackAttempted = true
      const completion = await query('ROLLBACK')
      if (completion?.command !== 'ROLLBACK') {
        throw new TypeError('Read-only transaction did not confirm ROLLBACK')
      }
      finished = true
      return result
    } catch (error) {
      if (!rollbackAttempted) {
        try {
          await query('ROLLBACK')
        } catch {
          // รักษา error เดิมและทิ้ง connection หากยืนยัน state ไม่ได้
        }
      }
      throw error
    } finally {
      const discard = !finished || connectionError !== null
      client.release(discard)
      if (!discard) client.removeListener('error', onConnectionError)
    }
  }
}
