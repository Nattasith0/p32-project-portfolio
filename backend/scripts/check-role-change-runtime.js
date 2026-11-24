import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import { pathToFileURL } from 'node:url'
import { createRoleChangeRuntimeRepository } from '../src/modules/roles/role-change.runtime.repository.js'
import {
  createRoleChangeService,
  RoleChangeError,
} from '../src/modules/roles/role-change.service.js'

const LIMITS = { statement: '5s', lock: '2s', idle: '15s' }
const query = (client, text, values) =>
  client.query({ text, values, query_timeout: 10000 })
const readLimits = async (client) =>
  (
    await query(
      client,
      `SELECT
  current_setting('statement_timeout') AS statement,
  current_setting('lock_timeout') AS lock,
  current_setting('idle_in_transaction_session_timeout') AS idle`,
    )
  ).rows[0]

async function verifyTarget(client) {
  const target = (
    await query(
      client,
      `SELECT current_user AS db_user,
    current_database() AS db_name,
    current_setting('is_superuser')::boolean AS is_superuser,
    host(inet_server_addr()) AS server_address`,
    )
  ).rows[0]
  assert.equal(target.db_user, 'p32_app')
  assert.equal(target.db_name, 'p32_dev')
  assert.equal(target.is_superuser, false)
  assert.ok(['127.0.0.1', '::1'].includes(target.server_address))
}

// ใช้ pool development เฉพาะการตรวจนี้; CLI ปิด pool เมื่อเสร็จ
export async function checkRoleChangeRuntime(pool, onStep = () => {}) {
  let observer
  let locker
  const requestIds = Array.from({ length: 4 }, () => randomUUID())
  const timings = []

  try {
    onStep('database target')
    observer = await pool.connect()
    observer.on('error', () => {})
    await verifyTarget(observer)

    onStep('demo account guards')
    const users = (
      await query(
        observer,
        `SELECT user_id, username, is_active,
      email_verified_at IS NOT NULL AS verified FROM p32.users
      WHERE username IN ('admin_demo', 'student_demo')`,
      )
    ).rows
    assert.equal(users.length, 2)
    const admin = users.find((row) => row.username === 'admin_demo')
    const student = users.find((row) => row.username === 'student_demo')
    assert.ok(admin?.is_active && admin.verified)
    assert.ok(student?.is_active && student.verified)
    const userIds = [admin.user_id, student.user_id]
    const snapshot = async (client) => ({
      roles: (
        await query(
          client,
          `SELECT user_id, role_code, assigned_by, assigned_at
        FROM p32.user_roles WHERE user_id = ANY($1::uuid[]) ORDER BY user_id, role_code`,
          [userIds],
        )
      ).rows,
      audit: (
        await query(
          client,
          `SELECT * FROM p32.user_role_audit
        WHERE target_user_id = ANY($1::uuid[]) ORDER BY audit_id`,
          [userIds],
        )
      ).rows,
    })
    const before = await snapshot(observer)
    assert.ok(
      before.roles.some(
        (row) => row.user_id === admin.user_id && row.role_code === 'system_admin',
      ),
    )
    assert.ok(
      before.roles.some(
        (row) => row.user_id === student.user_id && row.role_code === 'student',
      ),
    )
    assert.ok(
      !before.roles.some(
        (row) => row.user_id === student.user_id && row.role_code === 'system_admin',
      ),
    )

    // No-op/forbidden ใช้ SQL function จริง ส่วน timeout แทนเฉพาะ SQL สุดท้าย
    // ด้วยคำสั่งอ่านอย่างเดียวเพื่อไม่ต้องเปลี่ยนบทบาทจริงในการทดสอบ timeout
    function createService(mode) {
      const stats = { calls: 0, releases: [] }
      const guardedPool = {
        async connect() {
          const client = await pool.connect()
          const onError = () => {}
          client.on('error', onError)
          let baseline
          try {
            await verifyTarget(client)
            baseline = await readLimits(client)
          } catch (error) {
            client.release(true)
            throw error
          }

          const facade = {
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
              if (config.text.includes('FROM p32.change_user_role')) {
                stats.calls += 1
                assert.deepEqual(await readLimits(client), LIMITS)
                if (mode === 'statement-timeout') {
                  return query(client, 'SELECT pg_sleep(6)')
                }
                if (mode === 'lock-timeout') {
                  return query(
                    client,
                    'SELECT user_id FROM p32.users WHERE user_id = $1 FOR SHARE',
                    [student.user_id],
                  )
                }

                const lock = await query(
                  client,
                  'SELECT pg_try_advisory_xact_lock(32, 1) AS acquired',
                )
                assert.equal(lock.rows[0].acquired, true)
                assert.deepEqual(await snapshot(client), before)
                const response = await client.query(config)
                if (mode === 'forbidden')
                  assert.fail('Expected the database to reject the actor')
                assert.deepEqual(response.rows, [{ changed: false, audit_id: null }])
                // ถ้า function เขียนข้อมูลโดยไม่คาดหมาย ต้องหยุดก่อน COMMIT
                assert.deepEqual(await snapshot(client), before)
                return response
              }
              const response = await client.query(config)
              if (config.text === 'COMMIT' || config.text === 'ROLLBACK') {
                assert.deepEqual(await readLimits(client), baseline)
              }
              return response
            },
          }
          return facade
        },
      }
      return {
        service: createRoleChangeService({
          roleChangeRepository: createRoleChangeRuntimeRepository(guardedPool),
        }),
        stats,
      }
    }

    const context = {
      actorUserId: admin.user_id,
      requestId: requestIds[0],
      input: {
        targetUserId: student.user_id,
        roleCode: 'student',
        action: 'assign',
        reason: 'ตรวจ runtime แบบไม่เปลี่ยนบทบาท',
      },
    }

    onStep('no-op and committed local-settings reset')
    const noop = createService('no-op')
    assert.deepEqual(await noop.service.changeUserRole(context), {
      changed: false,
      auditId: null,
    })
    assert.equal(noop.stats.calls, 1)
    assert.deepEqual(noop.stats.releases, [false])

    onStep('forbidden actor and rollback')
    const forbidden = createService('forbidden')
    await assert.rejects(
      forbidden.service.changeUserRole({
        ...context,
        actorUserId: student.user_id,
        requestId: requestIds[1],
      }),
      (error) => error instanceof RoleChangeError && error.code === 'FORBIDDEN',
    )
    assert.equal(forbidden.stats.calls, 1)
    assert.deepEqual(forbidden.stats.releases, [true])

    onStep('server statement timeout on read-only SQL')
    const slow = createService('statement-timeout')
    let started = performance.now()
    await assert.rejects(
      slow.service.changeUserRole({ ...context, requestId: requestIds[2] }),
      (error) => error.code === '57014',
    )
    timings.push({
      check: 'statement_timeout',
      milliseconds: Math.round(performance.now() - started),
    })
    assert.equal(slow.stats.calls, 1)
    assert.deepEqual(slow.stats.releases, [true])

    onStep('row lock held by a separate connection')
    locker = await pool.connect()
    locker.on('error', () => {})
    await verifyTarget(locker)
    await query(locker, 'BEGIN ISOLATION LEVEL READ COMMITTED')
    await query(locker, "SET LOCAL statement_timeout = '5s'")
    await query(locker, "SET LOCAL lock_timeout = '2s'")
    await query(locker, "SET LOCAL idle_in_transaction_session_timeout = '15s'")
    await query(locker, 'SELECT user_id FROM p32.users WHERE user_id = $1 FOR UPDATE', [
      student.user_id,
    ])
    onStep('server lock timeout on read-only SQL')
    const locked = createService('lock-timeout')
    started = performance.now()
    await assert.rejects(
      locked.service.changeUserRole({ ...context, requestId: requestIds[3] }),
      (error) => error.code === '55P03',
    )
    timings.push({
      check: 'lock_timeout',
      milliseconds: Math.round(performance.now() - started),
    })
    assert.equal(locked.stats.calls, 1)
    assert.deepEqual(locked.stats.releases, [true])
    await query(locker, 'ROLLBACK')
    locker.release(true)
    locker = null

    onStep('unchanged roles and audit')
    assert.deepEqual(await snapshot(observer), before)
    const count = (
      await query(
        observer,
        `SELECT count(*)::integer AS count
      FROM p32.user_role_audit WHERE request_id = ANY($1::uuid[])`,
        [requestIds],
      )
    ).rows[0].count
    assert.equal(count, 0)
    return timings
  } finally {
    if (locker) {
      try {
        await query(locker, 'ROLLBACK')
      } catch {
        // หาก connection ขาด จะทิ้ง client ต่อและคงข้อผิดพลาดหลักไว้
      } finally {
        locker.release(true)
      }
    }
    if (observer) observer.release(true)
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
    const timings = await checkRoleChangeRuntime(pool, (name) => {
      stage = name
    })
    console.table(timings)
    console.log('Role change runtime database checks passed; roles and audit unchanged.')
  } catch (error) {
    console.error(
      `Role change runtime check failed: ${stage} (${error.code ?? 'CHECK_FAILED'})`,
    )
    process.exitCode = 1
  } finally {
    if (pool) await pool.end()
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await main()
