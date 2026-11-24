import assert from 'node:assert/strict'
import { performance } from 'node:perf_hooks'
import { pathToFileURL } from 'node:url'
import { createUserSearchRuntimeRepository } from '../src/modules/users/user-search.runtime.repository.js'
import { createUserSearchService } from '../src/modules/users/user-search.service.js'

const LIMITS = {
  read_only: 'on',
  isolation: 'read committed',
  statement: '5s',
  lock: '2s',
  idle: '15s',
}
const query = (client, text, values) =>
  client.query({ text, values, query_timeout: 10000 })
const readSettings = async (client) =>
  (
    await query(
      client,
      `
  SELECT current_setting('transaction_read_only') AS read_only,
         current_setting('transaction_isolation') AS isolation,
         current_setting('statement_timeout') AS statement,
         current_setting('lock_timeout') AS lock,
         current_setting('idle_in_transaction_session_timeout') AS idle
`,
    )
  ).rows[0]

async function verifyTarget(client) {
  const row = (
    await query(
      client,
      `
    SELECT current_user AS db_user, current_database() AS db_name,
           current_setting('is_superuser')::boolean AS is_superuser,
           host(inet_server_addr()) AS server_address
  `,
    )
  ).rows[0]
  assert.equal(row.db_user, 'p32_app')
  assert.equal(row.db_name, 'p32_dev')
  assert.equal(row.is_superuser, false)
  assert.ok(['127.0.0.1', '::1'].includes(row.server_address))
}

async function beginReadOnly(client) {
  await query(client, 'BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY')
  await query(client, "SET LOCAL statement_timeout = '5s'")
  await query(client, "SET LOCAL lock_timeout = '2s'")
  await query(client, "SET LOCAL idle_in_transaction_session_timeout = '15s'")
}

export async function checkUserSearchRuntime(pool, onStep = () => {}) {
  let observer
  let locker
  let primaryFailure
  const timings = []

  try {
    onStep('database target')
    observer = await pool.connect()
    observer.on('error', () => {})
    await verifyTarget(observer)
    await beginReadOnly(observer)

    const snapshot = async () =>
      (
        await query(
          observer,
          `
      SELECT user_id, username, display_name, is_active,
             email_verified_at IS NOT NULL AS email_verified
      FROM p32.users WHERE username IN ('admin_demo', 'student_demo') ORDER BY user_id
    `,
        )
      ).rows

    onStep('development demo accounts')
    const before = await snapshot()
    assert.equal(before.length, 2)
    const student = before.find((row) => row.username === 'student_demo')
    assert.ok(student?.is_active && student.email_verified)

    function createService(mode) {
      const stats = { searches: 0, releases: [] }
      const guardedPool = {
        async connect() {
          const client = await pool.connect()
          const onError = () => {}
          client.on('error', onError)
          let baseline
          try {
            await verifyTarget(client)
            baseline = await readSettings(client)
          } catch (error) {
            client.release(true)
            throw error
          }
          return {
            on(name, listener) {
              client.on(name, listener)
            },
            removeListener(name, listener) {
              client.removeListener(name, listener)
            },
            release(discard) {
              stats.releases.push(discard)
              client.release(discard)
              if (!discard) client.removeListener('error', onError)
            },
            async query(config) {
              if (config.text.includes('FROM p32.users')) {
                stats.searches += 1
                assert.deepEqual(await readSettings(client), LIMITS)
                // เปลี่ยนเฉพาะ SELECT สุดท้ายเป็นคำสั่งทดสอบ ไม่แก้โค้ด runtime
                if (mode === 'statement-timeout')
                  return query(client, 'SELECT pg_sleep(6)')
                if (mode === 'lock-timeout')
                  return query(client, 'SELECT pg_advisory_xact_lock(32, 2)')
                if (mode === 'query-error') return query(client, 'SELECT 1 / 0')
              }
              const result = await client.query(config)
              if (config.text === 'ROLLBACK') {
                assert.deepEqual(await readSettings(client), baseline)
              }
              return result
            },
          }
        },
      }
      return {
        service: createUserSearchService({
          userSearchRepository: createUserSearchRuntimeRepository(guardedPool),
        }),
        stats,
      }
    }

    onStep('real search and transaction settings reset')
    const normal = createService('search')
    const result = await normal.service.searchUsers({ q: 'student_demo' })
    assert.deepEqual(
      result.users.find((user) => user.userId === student.user_id),
      {
        userId: student.user_id,
        username: student.username,
        displayName: student.display_name,
        isActive: student.is_active,
        emailVerified: student.email_verified,
      },
    )
    assert.equal(normal.stats.searches, 1)
    assert.deepEqual(normal.stats.releases, [false])

    onStep('database error and rollback')
    const broken = createService('query-error')
    await assert.rejects(
      broken.service.searchUsers({ q: 'student_demo' }),
      (error) => error.code === '22012',
    )
    assert.equal(broken.stats.searches, 1)
    assert.deepEqual(broken.stats.releases, [true])

    onStep('server statement timeout on read-only SQL')
    const slow = createService('statement-timeout')
    let started = performance.now()
    await assert.rejects(
      slow.service.searchUsers({ q: 'student_demo' }),
      (error) => error.code === '57014',
    )
    timings.push({
      check: 'statement_timeout',
      milliseconds: Math.round(performance.now() - started),
    })
    assert.equal(slow.stats.searches, 1)
    assert.deepEqual(slow.stats.releases, [true])

    onStep('separate read-only connection holds the test advisory lock')
    locker = await pool.connect()
    locker.on('error', () => {})
    await verifyTarget(locker)
    await beginReadOnly(locker)
    const acquired = await query(
      locker,
      'SELECT pg_try_advisory_xact_lock(32, 2) AS acquired',
    )
    assert.equal(acquired.rows[0].acquired, true)

    onStep('server lock timeout on read-only SQL')
    const locked = createService('lock-timeout')
    started = performance.now()
    await assert.rejects(
      locked.service.searchUsers({ q: 'student_demo' }),
      (error) => error.code === '55P03',
    )
    timings.push({
      check: 'lock_timeout',
      milliseconds: Math.round(performance.now() - started),
    })
    assert.equal(locked.stats.searches, 1)
    assert.deepEqual(locked.stats.releases, [true])
    await query(locker, 'ROLLBACK')
    locker.release(true)
    locker = null

    onStep('test lock released and demo account snapshot unchanged')
    assert.equal(
      (await query(observer, 'SELECT pg_try_advisory_xact_lock(32, 2) AS acquired'))
        .rows[0].acquired,
      true,
    )
    assert.deepEqual(await snapshot(), before)
    return timings
  } catch (error) {
    primaryFailure = error
    throw error
  } finally {
    let cleanupFailure
    for (const client of [locker, observer]) {
      if (!client) continue
      try {
        await query(client, 'ROLLBACK')
      } catch (error) {
        cleanupFailure ??= error
      } finally {
        client.release(true)
      }
    }
    if (!primaryFailure && cleanupFailure) throw cleanupFailure
  }
}

async function main() {
  let pool
  let stage = 'development settings'
  try {
    assert.equal(process.env.NODE_ENV, 'development')
    assert.ok(['127.0.0.1', 'localhost', '::1'].includes(process.env.PGHOST))
    assert.equal(process.env.PGUSER, 'p32_app')
    assert.equal(process.env.PGDATABASE, 'p32_dev')
    stage = 'database connection'
    const databaseModule = await import('../src/database/pool.js')
    pool = databaseModule.pool
    const timings = await checkUserSearchRuntime(pool, (name) => {
      stage = name
    })
    console.table(timings)
    console.log(
      'User search runtime database checks passed; read-only transactions closed.',
    )
  } catch (error) {
    const code =
      typeof error?.code === 'string' &&
      error.code.length === 5 &&
      /^[0-9A-Z]{5}$/.test(error.code)
        ? error.code
        : 'CHECK_FAILED'
    console.error(`User search runtime check failed: ${stage} (${code})`)
    process.exitCode = 1
  } finally {
    if (pool) await pool.end()
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await main()
