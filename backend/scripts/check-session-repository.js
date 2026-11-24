import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { pool } from '../src/database/pool.js'
import { createSessionRepository } from '../src/modules/auth/session.repository.js'

const demoUsernames = ['student_demo', 'admin_demo']

const demoUsersQuery = `
  SELECT user_id, username, is_active, updated_at
  FROM p32.users
  WHERE username IN ($1, $2)
  ORDER BY username
`

let client
let checkName = 'database target'

try {
    assert.ok(['127.0.0.1', 'localhost', '::1'].includes(process.env.PGHOST))

    client = await pool.connect()

    const target = await client.query(`
    SELECT current_user AS db_user, current_database() AS db_name
  `)

    assert.equal(target.rows[0].db_user, 'p32_app')
    assert.equal(target.rows[0].db_name, 'p32_dev')

    checkName = 'demo accounts'

    const usersBefore = await client.query(demoUsersQuery, demoUsernames)
    const student = usersBefore.rows.find((user) => user.username === 'student_demo')
    const admin = usersBefore.rows.find((user) => user.username === 'admin_demo')

    assert.ok(student)
    assert.ok(admin)

    const repository = createSessionRepository(client)
    const sessionId = randomUUID()
    const expiredSessionId = randomUUID()
    const lookup = { sessionId, userId: student.user_id }
    const testDigest = 'a'.repeat(64)

    await client.query('BEGIN')

    try {
        checkName = 'active session'

        await repository.createSession({
            sessionId,
            userId: student.user_id,
            csrfTokenHash: testDigest,
            expiresAt: new Date(Date.now() + 30 * 60 * 1000),
        })

        const active = await repository.findActiveSession(lookup)

        assert.ok(active)
        assert.equal(active.session_id, sessionId)
        assert.equal(active.user_id, student.user_id)
        assert.equal(active.username, 'student_demo')
        assert.equal(active.csrf_token_hash, testDigest)

        checkName = 'wrong owner'

        assert.equal(await repository.findActiveSession({
            sessionId,
            userId: admin.user_id,
        }), null)

        checkName = 'missing session'

        assert.equal(await repository.findActiveSession({
            sessionId: randomUUID(),
            userId: student.user_id,
        }), null)

        checkName = 'expired session'

        await client.query(
            `
        INSERT INTO p32.auth_sessions (
          session_id, user_id, csrf_token_hash, created_at, expires_at
        )
        VALUES (
          $1, $2, $3,
          statement_timestamp() - interval '2 hours',
          statement_timestamp() - interval '1 hour'
        )
      `,
            [expiredSessionId, student.user_id, testDigest]
        )

        assert.equal(await repository.findActiveSession({
            sessionId: expiredSessionId,
            userId: student.user_id,
        }), null)

        checkName = 'inactive account'

        await client.query('SAVEPOINT before_disabled_account')

        await client.query(
            `
        UPDATE p32.users
        SET is_active = FALSE, updated_at = statement_timestamp()
        WHERE user_id = $1
      `,
            [student.user_id]
        )

        assert.equal(await repository.findActiveSession(lookup), null)

        await client.query('ROLLBACK TO SAVEPOINT before_disabled_account')

        assert.ok(await repository.findActiveSession(lookup))

            checkName = 'revoke wrong owner'

    assert.equal(await repository.revokeSession({
      sessionId,
      userId: admin.user_id,
    }), false)

    assert.ok(await repository.findActiveSession(lookup))

    checkName = 'revoke missing session'

    assert.equal(await repository.revokeSession({
      sessionId: randomUUID(),
      userId: student.user_id,
    }), false)

    checkName = 'revoke owned session'

    assert.equal(await repository.revokeSession(lookup), true)
    assert.equal(await repository.findActiveSession(lookup), null)

    const firstRevocation = await client.query(
      `
        SELECT revoked_at::text AS revoked_at
        FROM p32.auth_sessions
        WHERE session_id = $1
      `,
      [sessionId]
    )

    assert.equal(firstRevocation.rows.length, 1)
    assert.ok(firstRevocation.rows[0].revoked_at)

    checkName = 'repeat revocation'

    assert.equal(await repository.revokeSession(lookup), false)

    const repeatedRevocation = await client.query(
      `
        SELECT revoked_at::text AS revoked_at
        FROM p32.auth_sessions
        WHERE session_id = $1
      `,
      [sessionId]
    )

    assert.deepEqual(
      repeatedRevocation.rows,
      firstRevocation.rows
    )

    checkName = 'revoke expired session'

    assert.equal(await repository.revokeSession({
      sessionId: expiredSessionId,
      userId: student.user_id,
    }), true)

        assert.equal(await repository.findActiveSession(lookup), null)
    } finally {
        await client.query('ROLLBACK')
    }

    checkName = 'rollback cleanup'

    const remaining = await client.query(
        `
      SELECT session_id
      FROM p32.auth_sessions
      WHERE session_id IN ($1, $2)
    `,
        [sessionId, expiredSessionId]
    )

    assert.equal(remaining.rowCount, 0)

    const usersAfter = await client.query(demoUsersQuery, demoUsernames)
    assert.deepEqual(usersAfter.rows, usersBefore.rows)

    console.log('Session repository checks passed; test data rolled back.')
} catch (error) {
    console.error(
        `Session repository checks failed (${checkName}):`,
        error.code ?? error.name
    )
    process.exitCode = 1
} finally {
    if (client) {
        client.release(true)
    }

    await pool.end()
}