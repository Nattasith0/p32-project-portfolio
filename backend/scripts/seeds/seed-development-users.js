import {
    hashPassword,
    verifyPassword,
} from '../../src/security/password.js'
import { DEVELOPMENT_USERS } from './development-users.js'

function createSeedError(code) {
    const error = new Error(code)
    error.code = code
    return error
}

async function createOrValidateUser(client, definition, password) {
    const existingResult = await client.query(
        `
      SELECT
        username,
        email,
        display_name,
        password_hash,
        is_active,
        email_verified_at
      FROM p32.users
      WHERE user_id = $1
      FOR UPDATE
    `,
        [definition.userId]
    )

    const existing = existingResult.rows[0]

    if (existing) {
        const accountMatches =
            existing.username === definition.username &&
            existing.email === definition.email &&
            existing.display_name === definition.displayName &&
            existing.is_active === true &&
            existing.email_verified_at !== null

        if (!accountMatches) {
            throw createSeedError('DEV_SEED_ACCOUNT_CONFLICT')
        }

        const passwordMatches = await verifyPassword(
            existing.password_hash,
            password
        )

        if (!passwordMatches) {
            throw createSeedError('DEV_SEED_PASSWORD_CONFLICT')
        }

        const roleResult = await client.query(
            `
        SELECT role_code, assigned_by
        FROM p32.user_roles
        WHERE user_id = $1
      `,
            [definition.userId]
        )

        const assignment = roleResult.rows[0]

        if (
            roleResult.rows.length !== 1 ||
            assignment.role_code !== definition.roleCode ||
            assignment.assigned_by !== definition.assignedByUserId
        ) {
            throw createSeedError('DEV_SEED_ROLE_CONFLICT')
        }

        return {
            username: definition.username,
            role: definition.roleCode,
            action: 'unchanged',
        }
    }

    const passwordHash = await hashPassword(password)

    // จำลองสถานะยืนยันอีเมลเฉพาะข้อมูลทดสอบในฐานพัฒนา
    await client.query(
        `
      INSERT INTO p32.users (
        user_id,
        username,
        email,
        display_name,
        password_hash,
        email_verified_at,
        is_active
      )
      VALUES ($1, $2, $3, $4, $5, now(), TRUE)
    `,
        [
            definition.userId,
            definition.username,
            definition.email,
            definition.displayName,
            passwordHash,
        ]
    )

    await client.query(
        `
      INSERT INTO p32.user_roles (
        user_id,
        role_code,
        assigned_by
      )
      VALUES ($1, $2, $3)
    `,
        [
            definition.userId,
            definition.roleCode,
            definition.assignedByUserId,
        ]
    )

    return {
        username: definition.username,
        role: definition.roleCode,
        action: 'created',
    }
}

// เรียกด้วย client และค่าตั้งที่ผ่าน preflight จากสคริปต์หลักแล้ว
export async function seedDevelopmentUsers(
    client,
    environment = process.env
) {
    await client.query('BEGIN')

    try {
        const lockResult = await client.query(`
      SELECT pg_try_advisory_xact_lock(32, 1) AS acquired
    `)

        if (!lockResult.rows[0].acquired) {
            throw createSeedError('DEV_SEED_BUSY')
        }

        const results = []

        for (const definition of DEVELOPMENT_USERS) {
            const password = environment[definition.passwordEnvName]

            const result = await createOrValidateUser(
                client,
                definition,
                password
            )

            results.push(result)
        }

        await client.query('COMMIT')
        return results
    } catch (error) {
        await client.query('ROLLBACK')
        throw error
    }
}