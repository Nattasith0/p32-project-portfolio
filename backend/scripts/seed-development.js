import { pool } from '../src/database/pool.js'
import { seedDevelopmentUsers } from './seeds/seed-development-users.js'
import { MAX_PASSWORD_LENGTH } from '../src/security/password-policy.js'

const LOCAL_DATABASE_HOSTS = ['127.0.0.1', 'localhost', '::1']

const PASSWORD_VARIABLES = [
    'P32_SEED_ADMIN_PASSWORD',
    'P32_SEED_STUDENT_PASSWORD',
]

function rejectSeed(message) {
    console.error(message)
    process.exitCode = 1
}

async function runDevelopmentSeed() {
    const mode = process.argv[2] ?? 'check'
    let client

    try {
        if (!['check', 'seed'].includes(mode)) {
            rejectSeed('Use seed mode: check or seed')
            return
        }

        if (
            process.env.NODE_ENV !== 'development' ||
            process.env.P32_ALLOW_DEV_SEED !== 'true'
        ) {
            rejectSeed(
                'Development seed requires NODE_ENV=development and P32_ALLOW_DEV_SEED=true'
            )
            return
        }

        if (
            !LOCAL_DATABASE_HOSTS.includes(process.env.PGHOST) ||
            process.env.PGDATABASE !== 'p32_dev' ||
            process.env.PGUSER !== 'p32_migrator'
        ) {
            rejectSeed(
                'Seed target rejected: expected local p32_migrator on p32_dev'
            )
            return
        }

        for (const name of PASSWORD_VARIABLES) {
            const password = process.env[name]

            if (typeof password !== 'string') {
                rejectSeed(`${name} must be configured`)
                return
            }

            const passwordLength = Array.from(password).length

            if (
                passwordLength < 15 ||
                passwordLength > MAX_PASSWORD_LENGTH
            ) {
                rejectSeed(
                    `${name} must contain 15 to ${MAX_PASSWORD_LENGTH} Unicode code points`
                )
                return
            }
        }

        if (
            process.env.P32_SEED_ADMIN_PASSWORD ===
            process.env.P32_SEED_STUDENT_PASSWORD
        ) {
            rejectSeed('Development seed passwords must be different')
            return
        }

        client = await pool.connect()

        const result = await client.query(`
      SELECT
        current_user AS db_user,
        current_database() AS db_name,
        rolsuper AS is_superuser
      FROM pg_catalog.pg_roles
      WHERE rolname = current_user
    `)

        const target = result.rows[0]

        if (
            !target ||
            target.db_user !== 'p32_migrator' ||
            target.db_name !== 'p32_dev' ||
            target.is_superuser
        ) {
            rejectSeed(
                'Seed connection rejected: expected non-superuser p32_migrator on p32_dev'
            )
            return
        }

        console.table(result.rows)

        if (mode === 'check') {
            console.log(
                'Development seed preflight passed. No data was changed.'
            )
            return
        }

        const seedResults = await seedDevelopmentUsers(client)

        console.table(seedResults)
        console.log('Development seed completed.')
    } catch (error) {
        console.error('Development seed failed:', error.code ?? 'UNKNOWN')
        process.exitCode = 1
    } finally {
        if (client) {
            client.release(true)
        }

        await pool.end()
    }
}

await runDevelopmentSeed()