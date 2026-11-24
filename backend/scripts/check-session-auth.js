import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { pool } from '../src/database/pool.js'
import { createCsrfProtection } from '../src/security/csrf.js'
import { createJwtService } from '../src/security/jwt.js'
import { createSessionRepository } from '../src/modules/auth/session.repository.js'
import { createSessionService } from '../src/modules/auth/session.service.js'
import { createSessionAuthService } from '../src/modules/auth/session-auth.service.js'

const demoUsernames = ['student_demo', 'admin_demo']

const usersQuery = `
  SELECT
    user_id,
    username,
    display_name,
    is_active,
    email_verified_at::text AS email_verified_at,
    updated_at::text AS updated_at
  FROM p32.users
  WHERE username IN ($1, $2)
  ORDER BY username
`

const sessionIds = []
let client
let checkName = 'database target'

try {
    assert.ok(
        ['127.0.0.1', 'localhost', '::1'].includes(process.env.PGHOST)
    )

    client = await pool.connect()

    const target = await client.query(`
    SELECT
      current_user AS db_user,
      current_database() AS db_name,
      current_setting('is_superuser') AS is_superuser
  `)

    assert.equal(target.rows[0].db_user, 'p32_app')
    assert.equal(target.rows[0].db_name, 'p32_dev')
    assert.equal(target.rows[0].is_superuser, 'off')

    checkName = 'development accounts'

    const usersBefore = await client.query(usersQuery, demoUsernames)

    const student = usersBefore.rows.find(
        (user) => user.username === 'student_demo'
    )
    const admin = usersBefore.rows.find(
        (user) => user.username === 'admin_demo'
    )

    assert.ok(student)
    assert.ok(admin)
    assert.equal(student.is_active, true)
    assert.ok(student.email_verified_at)

    // กุญแจชั่วคราวแยกสำหรับ JWT และ CSRF ไม่บันทึกหรือแสดงค่า
    const jwtSecretHex = randomBytes(32).toString('hex')

    const jwtService = createJwtService({
        secretHex: jwtSecretHex,
    })

    const csrfProtection = createCsrfProtection(
        randomBytes(32).toString('hex')
    )

    // ทุก Repository query ใช้ client เดียวกับ transaction
    const repository = createSessionRepository(client)

    const sessionService = createSessionService({
        sessionRepository: repository,
        csrfProtection,
    })

    const authService = createSessionAuthService({
        jwtService,
        sessionRepository: repository,
    })

    await client.query('BEGIN')

    try {
        checkName = 'valid JWT and active session'

        const session = await sessionService.startSession({
            userId: student.user_id,
        })

        sessionIds.push(session.sessionId)

        const token = await jwtService.signSession(session)

        const expected = {
            userId: student.user_id,
            username: student.username,
            displayName: student.display_name,
            sessionId: session.sessionId,
            expiresAt: session.expiresAt,
        }

        assert.deepEqual(
            await authService.authenticateSessionToken(token),
            expected
        )

        checkName = 'invalid JWT'

        assert.equal(
            await authService.authenticateSessionToken('not-a-jwt'),
            null
        )

        checkName = 'wrong session owner'

        const wrongOwnerToken = await jwtService.signSession({
            ...session,
            userId: admin.user_id,
        })

        assert.ok(await jwtService.verifySession(wrongOwnerToken))

        assert.equal(
            await authService.authenticateSessionToken(wrongOwnerToken),
            null
        )

        checkName = 'mismatched expiration'

        const shorterToken = await jwtService.signSession({
            ...session,
            expiresAt: new Date(session.expiresAt.getTime() - 1000),
        })

        assert.ok(await jwtService.verifySession(shorterToken))

        assert.equal(
            await authService.authenticateSessionToken(shorterToken),
            null
        )

        checkName = 'suspended account'

        await client.query('SAVEPOINT before_disabled_account')

        const disabled = await client.query(
            `
        UPDATE p32.users
        SET is_active = FALSE, updated_at = statement_timestamp()
        WHERE user_id = $1
      `,
            [student.user_id]
        )

        assert.equal(disabled.rowCount, 1)
        assert.ok(await jwtService.verifySession(token))

        assert.equal(
            await authService.authenticateSessionToken(token),
            null
        )

        await client.query(
            'ROLLBACK TO SAVEPOINT before_disabled_account'
        )

        assert.deepEqual(
            await authService.authenticateSessionToken(token),
            expected
        )

        checkName = 'expired JWT'

        const expiredJwtService = createJwtService({
            secretHex: jwtSecretHex,
            now: () => session.expiresAt.getTime(),
        })

        const expiredAuthService = createSessionAuthService({
            jwtService: expiredJwtService,
            sessionRepository: repository,
        })

        assert.equal(
            await expiredAuthService.authenticateSessionToken(token),
            null
        )

        checkName = 'revoked session'

        assert.equal(
            await repository.revokeSession({
                sessionId: session.sessionId,
                userId: student.user_id,
            }),
            true
        )

        // ลายเซ็นและเวลาของ JWT ยังผ่าน แต่ session ถูกเพิกถอนแล้ว
        assert.deepEqual(
            await jwtService.verifySession(token),
            session
        )

        assert.equal(
            await authService.authenticateSessionToken(token),
            null
        )
    } finally {
        await client.query('ROLLBACK')
    }

    checkName = 'rollback cleanup'

    const remaining = await client.query(
        `
      SELECT session_id
      FROM p32.auth_sessions
      WHERE session_id = ANY($1::uuid[])
    `,
        [sessionIds]
    )

    assert.equal(remaining.rowCount, 0)

    const usersAfter = await client.query(usersQuery, demoUsernames)
    assert.deepEqual(usersAfter.rows, usersBefore.rows)

    console.log(
        'JWT/session database checks passed; test data rolled back.'
    )
} catch (error) {
    console.error(
        `JWT/session database checks failed (${checkName}):`,
        error.code ?? error.name
    )
    process.exitCode = 1
} finally {
    if (client) {
        client.release(true)
    }

    await pool.end()
}