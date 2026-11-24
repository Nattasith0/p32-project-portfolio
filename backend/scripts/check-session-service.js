import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { pool } from '../src/database/pool.js'
import { createCsrfProtection } from '../src/security/csrf.js'
import { createSessionRepository } from '../src/modules/auth/session.repository.js'
import { createSessionService } from '../src/modules/auth/session.service.js'

let client
let checkName = 'database target'

const sessionIds = []

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

    checkName = 'development account'

    const users = await client.query(
        `
      SELECT user_id
      FROM p32.users
      WHERE username = $1
        AND is_active = TRUE
        AND email_verified_at IS NOT NULL
    `,
        ['student_demo']
    )

    assert.equal(users.rows.length, 1)

    const userId = users.rows[0].user_id

    // กุญแจชั่วคราวสำหรับการตรวจครั้งนี้ ไม่บันทึกลงไฟล์
    const csrfProtection = createCsrfProtection(
        randomBytes(32).toString('hex')
    )

    // ใช้ client เดียวกัน เพื่อให้ทุกคำสั่งอยู่ใน transaction เดียว
    const repository = createSessionRepository(client)
    const service = createSessionService({
        sessionRepository: repository,
        csrfProtection,
    })

    const activeSessions = []
    const tokens = []

    await client.query('BEGIN')

    try {
        for (let index = 0; index < 2; index += 1) {
            checkName = `create session ${index + 1}`

            const before = Date.now()
            const result = await service.startSession({ userId })
            const after = Date.now()

            sessionIds.push(result.sessionId)

            assert.deepEqual(Object.keys(result).sort(), [
                'expiresAt',
                'sessionId',
                'userId',
            ])
            assert.equal(result.userId, userId)

            const lifetime = 30 * 60 * 1000
            const expiration = result.expiresAt.getTime()

            assert.ok(
                expiration >= Math.floor(before / 1000) * 1000 + lifetime
            )
            assert.ok(
                expiration <= Math.floor(after / 1000) * 1000 + lifetime
            )

            checkName = `read session ${index + 1}`

            const active = await repository.findActiveSession({
                sessionId: result.sessionId,
                userId,
            })

            assert.ok(active)
            assert.equal(active.user_id, userId)
            assert.equal(active.expires_at.getTime(), expiration)

            const token = csrfProtection.createToken({
                sessionId: result.sessionId,
                userId,
            })

            assert.equal(
                active.csrf_token_hash,
                csrfProtection.hashToken(token)
            )

            assert.equal(csrfProtection.verifyToken(token, {
                sessionId: active.session_id,
                userId: active.user_id,
                csrfTokenHash: active.csrf_token_hash,
            }), true)

            activeSessions.push(active)
            tokens.push(token)
        }

        checkName = 'session isolation'

        assert.notEqual(sessionIds[0], sessionIds[1])
        assert.notEqual(
            activeSessions[0].csrf_token_hash,
            activeSessions[1].csrf_token_hash
        )

        const second = activeSessions[1]

        // Token ของ session แรกต้องใช้กับ session ที่สองไม่ได้
        assert.equal(csrfProtection.verifyToken(tokens[0], {
            sessionId: second.session_id,
            userId: second.user_id,
            csrfTokenHash: second.csrf_token_hash,
        }), false)

        const firstContext = {
            sessionId: sessionIds[0],
            userId,
        }

        checkName = 'retrieve the same CSRF token'

        assert.equal(
            await service.getCsrfToken(firstContext),
            tokens[0]
        )
        assert.equal(
            await service.getCsrfToken(firstContext),
            tokens[0]
        )

        checkName = 'reject a changed CSRF key'

        const rotatedService = createSessionService({
            sessionRepository: repository,
            csrfProtection: createCsrfProtection(
                randomBytes(32).toString('hex')
            ),
        })

        assert.equal(
            await rotatedService.getCsrfToken(firstContext),
            null
        )

        // กุญแจเดิมยังขอ token ของ session เดิมได้
        assert.equal(
            await service.getCsrfToken(firstContext),
            tokens[0]
        )

        checkName = 'reject a revoked session'

        assert.equal(
            await repository.revokeSession(firstContext),
            true
        )
        assert.equal(
            await service.getCsrfToken(firstContext),
            null
        )

        // เพิกถอน session แรกต้องไม่กระทบ session ที่สอง
        assert.equal(
            await service.getCsrfToken({
                sessionId: sessionIds[1],
                userId,
            }),
            tokens[1]
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

    console.log(
        'Session service checks passed; test data rolled back.'
    )
} catch (error) {
    console.error(
        `Session service checks failed (${checkName}):`,
        error.code ?? error.name
    )
    process.exitCode = 1
} finally {
    if (client) {
        client.release(true)
    }

    await pool.end()
}
