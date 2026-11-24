import { fileURLToPath } from 'node:url'
import { runner } from 'node-pg-migrate'
import { pool } from '../src/database/pool.js'

async function runMigrations() {
    const mode = process.argv[2] ?? 'check'
    let client

    try {
        if (!['check', 'up'].includes(mode)) {
            console.error('Use migration mode: check or up')
            process.exitCode = 1
            return
        }

        client = await pool.connect()

        const result = await client.query(`
      SELECT
        current_user AS db_user,
        current_database() AS db_name,
        rolsuper AS is_superuser
      FROM pg_roles
      WHERE rolname = current_user
    `)

        const target = result.rows[0]

        if (
            target.db_user !== 'p32_migrator' ||
            target.db_name !== 'p32_dev' ||
            target.is_superuser
        ) {
            console.error(
                'Migration target rejected: expected non-superuser p32_migrator on p32_dev'
            )
            process.exitCode = 1
            return
        }

        console.table(result.rows)

        if (mode === 'check') {
            console.log('Migration preflight passed. No schema changes were made.')
            return
        }

        const migrations = await runner({
            dbClient: client,
            dir: fileURLToPath(new URL('../migrations/', import.meta.url)),
            direction: 'up',
            schema: 'p32',
            migrationsSchema: 'p32_meta',
            migrationsTable: 'schema_migrations',
            createMigrationsSchema: true,
            checkOrder: true,
            singleTransaction: true,
            noLock: false,
            logger: {
                info: console.log,
                warn: console.warn,
                error: () => console.error('Migration SQL operation failed'),
            },
        })

        console.log(`Applied ${migrations.length} migration(s).`)
    } catch (error) {
        console.error('Migration failed:', error.code ?? 'UNKNOWN')
        process.exitCode = 1
    } finally {
        if (client) {
            client.release(true)
        }

        await pool.end()
    }
}

await runMigrations()