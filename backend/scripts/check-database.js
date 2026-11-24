import { pool } from '../src/database/pool.js'

const query = `
  SELECT
    $1::text AS system,
    current_user AS db_user,
    current_database() AS db_name
`

try {
    const result = await pool.query(query, ['P32'])

    console.table(result.rows)
} catch (error) {
    console.error('Database check failed:', error.code ?? 'UNKNOWN')
    process.exitCode = 1
} finally {
    await pool.end()
}