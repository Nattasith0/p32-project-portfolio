import assert from 'node:assert/strict'
import { once } from 'node:events'
import { randomBytes, randomUUID } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { createApp } from '../src/app.js'
import { readAuthConfig } from '../src/config/auth.config.js'
import { createJwtService } from '../src/security/jwt.js'
import { createCsrfProtection } from '../src/security/csrf.js'
import { createLoginCsrfProtection } from '../src/security/login-csrf.js'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { createSessionRepository } from '../src/modules/auth/session.repository.js'
import { createSessionService } from '../src/modules/auth/session.service.js'
import { createSessionAuthService } from '../src/modules/auth/session-auth.service.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createAuthorizationRepository } from '../src/modules/authorization/authorization.repository.js'
import { createAuthorizationService } from '../src/modules/authorization/authorization.service.js'
import { createUserSearchRuntimeRepository } from '../src/modules/users/user-search.runtime.repository.js'
import { createUserSearchService } from '../src/modules/users/user-search.service.js'
import { createUserRolesRuntimeRepository } from '../src/modules/users/user-roles.runtime.repository.js'
import { createUserRolesService } from '../src/modules/users/user-roles.service.js'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const query = (client, text, values) =>
  client.query({ text, values, query_timeout: 10000 })
const dto = (row) => ({
  userId: row.user_id,
  username: row.username,
  displayName: row.display_name,
  isActive: row.is_active,
  emailVerified: row.email_verified,
})

async function verifyTarget(client) {
  const row = (
    await query(
      client,
      `
    SELECT current_user AS db_user, current_database() AS db_name,
           current_setting('is_superuser')::boolean AS is_superuser,
           host(inet_server_addr()) AS address
  `,
    )
  ).rows[0]
  assert.equal(row.db_user, 'p32_app')
  assert.equal(row.db_name, 'p32_dev')
  assert.equal(row.is_superuser, false)
  assert.ok(['127.0.0.1', '::1'].includes(row.address))
}

async function closeServer(server) {
  if (!server?.listening) return
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
    server.closeIdleConnections()
  })
}

export async function checkUserSearchHttp(pool, onStep = () => {}) {
  let client
  let server
  let transactionOpen = false
  let primaryFailure
  let phase = 'normal'
  let runtimeCalls = 0
  const sessionIds = []
  const logs = []

  try {
    onStep('database target and ready demo accounts')
    client = await pool.connect()
    client.on('error', () => {})
    await verifyTarget(client)
    const readDemos = async () =>
      (
        await query(
          client,
          `
      SELECT user_id, username, display_name, is_active,
             email_verified_at IS NOT NULL AS email_verified
      FROM p32.users WHERE username IN ('admin_demo', 'student_demo') ORDER BY user_id
    `,
        )
      ).rows
    const readSessions = async () =>
      (
        await query(
          client,
          `SELECT session_id, user_id, created_at, expires_at, revoked_at
        FROM p32.auth_sessions ORDER BY session_id`,
        )
      ).rows
    const beforeUsers = await readDemos()
    const beforeSessions = await readSessions()
    assert.equal(beforeUsers.length, 2)
    const admin = beforeUsers.find((row) => row.username === 'admin_demo')
    const student = beforeUsers.find((row) => row.username === 'student_demo')
    assert.ok(admin?.is_active && admin.email_verified)
    assert.ok(student?.is_active && student.email_verified)

    await query(client, 'BEGIN ISOLATION LEVEL READ COMMITTED')
    transactionOpen = true
    await query(client, "SET LOCAL statement_timeout = '5s'")
    await query(client, "SET LOCAL lock_timeout = '2s'")
    await query(client, "SET LOCAL idle_in_transaction_session_timeout = '30s'")

    const config = readAuthConfig({
      NODE_ENV: 'test',
      P32_WEB_ORIGIN: 'http://127.0.0.1',
      P32_JWT_SECRET_HEX: randomBytes(32).toString('hex'),
      P32_CSRF_SECRET_HEX: randomBytes(32).toString('hex'),
    })
    const database = { query: (text, values) => query(client, text, values) }
    const authorizationService = createAuthorizationService({
      authorizationRepository: createAuthorizationRepository(database),
    })
    assert.equal(
      await authorizationService.hasAnyRole({
        userId: admin.user_id,
        allowedRoles: ['system_admin'],
      }),
      true,
    )
    assert.equal(
      await authorizationService.hasAnyRole({
        userId: student.user_id,
        allowedRoles: ['system_admin'],
      }),
      false,
    )
    const sessionRepository = createSessionRepository(database)
    const sessionService = createSessionService({
      sessionRepository,
      csrfProtection: createCsrfProtection(config.csrfSecretHex),
    })
    const jwtService = createJwtService({ secretHex: config.jwtSecretHex })
    const sessionCookie = createSessionCookie(config.cookie)
    const requireSession = createRequireSession({
      sessionCookie,
      sessionAuthService: createSessionAuthService({ jwtService, sessionRepository }),
    })

    // Session อยู่ใน transaction ของ client หลัก ส่วนการอ่านบัญชีใช้ worker READ ONLY
    const guardedPool = {
      async connect() {
        const worker = await pool.connect()
        const onError = () => {}
        worker.on('error', onError)
        try {
          await verifyTarget(worker)
        } catch (error) {
          worker.release(true)
          throw error
        }
        return {
          on(name, listener) {
            worker.on(name, listener)
          },
          removeListener(name, listener) {
            worker.removeListener(name, listener)
          },
          release(discard) {
            worker.release(discard)
            if (!discard) worker.removeListener('error', onError)
          },
          async query(command) {
            if (command.text.includes('FROM p32.users')) {
              runtimeCalls += 1
              const state = (
                await query(
                  worker,
                  `SELECT current_setting('transaction_read_only') AS read_only,
              current_setting('statement_timeout') AS statement, current_setting('lock_timeout') AS lock`,
                )
              ).rows[0]
              assert.deepEqual(state, { read_only: 'on', statement: '5s', lock: '2s' })
              if (phase === 'query-error') return query(worker, 'SELECT 1 / 0')
            }
            return worker.query(command)
          },
        }
      },
    }
    const userSearchService = createUserSearchService({
      userSearchRepository: createUserSearchRuntimeRepository(guardedPool),
    })
    const userRolesService = createUserRolesService({
      userRolesRepository: createUserRolesRuntimeRepository(guardedPool),
    })
    const app = createApp({
      webOrigin: config.webOrigin,
      requireSession,
      authorizationService,
      userSearchService,
      userRolesService,
      authService: {
        async authenticateCredentials() {
          assert.fail('Search checks must not verify passwords')
        },
      },
      roleService: {
        async listRoles() {
          assert.fail('Search checks must not read the role catalog')
        },
      },
      roleChangeService: {
        async changeUserRole() {
          assert.fail('Search checks must not change roles')
        },
      },
      jwtService,
      sessionService,
      sessionRepository,
      sessionCookie,
      loginCsrfProtection: createLoginCsrfProtection({
        secretHex: config.csrfSecretHex,
      }),
      loginCsrfCookie: createLoginCsrfCookie(config.cookie.options),
      logger: {
        error(...args) {
          logs.push(args)
        },
      },
    })

    onStep('temporary sessions and loopback HTTP server')
    const sessions = {}
    const cookies = {}
    for (const [name, user] of [
      ['admin', admin],
      ['student', student],
    ]) {
      const session = await sessionService.startSession({ userId: user.user_id })
      sessions[name] = session
      sessionIds.push(session.sessionId)
      cookies[name] = `${config.cookie.name}=${await jwtService.signSession(session)}`
    }
    server = app.listen(0, '127.0.0.1')
    await once(server, 'listening')
    const base = `http://127.0.0.1:${server.address().port}`
    async function send(
      path = '/api/v1/admin/users?q=demo',
      { cookie = cookies.admin, method = 'GET', origin } = {},
    ) {
      const headers = {}
      if (cookie !== null) headers.Cookie = cookie
      if (origin !== undefined) headers.Origin = origin
      const response = await fetch(base + path, {
        method,
        headers,
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
      })
      const text = await response.text()
      return {
        status: response.status,
        headers: response.headers,
        body: text ? JSON.parse(text) : null,
      }
    }
    function publicHeaders(result) {
      assert.equal(result.headers.get('cache-control'), 'no-store')
      assert.match(result.headers.get('x-request-id'), UUID)
      assert.equal(result.headers.get('set-cookie'), null)
    }
    function failure(result, status, code) {
      publicHeaders(result)
      assert.equal(result.status, status)
      assert.equal(result.body.code, code)
      assert.equal(result.body.request_id, result.headers.get('x-request-id'))
      assert.deepEqual(Object.keys(result.body).sort(), [
        'code',
        'message',
        'request_id',
      ])
    }

    onStep('HTTP session, role and query guards before runtime search')
    failure(await send(undefined, { cookie: null }), 401, 'AUTH_REQUIRED')
    failure(
      await send(undefined, { cookie: `${config.cookie.name}=invalid` }),
      401,
      'AUTH_REQUIRED',
    )
    failure(await send(undefined, { cookie: cookies.student }), 403, 'FORBIDDEN')
    for (const path of [
      '/api/v1/admin/users',
      '/api/v1/admin/users?q=x',
      '/api/v1/admin/users?q=demo&q=student',
      '/api/v1/admin/users?q=demo&limit=51',
      '/api/v1/admin/users?q=demo&role=system_admin',
    ]) {
      failure(await send(path), 400, 'INVALID_USER_SEARCH_INPUT')
    }
    assert.equal(runtimeCalls, 0)

    onStep('admin HTTP cursor pages match the bounded database reference')
    const expected = (
      await query(
        client,
        `
      SELECT user_id, username, display_name, is_active,
             email_verified_at IS NOT NULL AS email_verified
      FROM p32.users WHERE username ILIKE '%demo%' OR display_name ILIKE '%demo%'
      ORDER BY user_id LIMIT 51
    `,
      )
    ).rows
    assert.ok(expected.length >= 2 && expected.length <= 50)
    const collected = []
    let after
    let completed = false
    for (let page = 0; page < 50; page += 1) {
      const result = await send(
        `/api/v1/admin/users?q=demo&limit=1${after ? `&after=${after}` : ''}`,
      )
      publicHeaders(result)
      assert.equal(result.status, 200)
      assert.equal(result.body.users.length, 1)
      assert.deepEqual(Object.keys(result.body).sort(), ['nextCursor', 'users'])
      const user = result.body.users[0]
      assert.deepEqual(Object.keys(user).sort(), [
        'displayName',
        'emailVerified',
        'isActive',
        'userId',
        'username',
      ])
      collected.push(user)
      if (result.body.nextCursor === null) {
        completed = true
        break
      }
      assert.equal(result.body.nextCursor, user.userId)
      after = result.body.nextCursor
    }
    assert.equal(completed, true)
    assert.deepEqual(collected, expected.map(dto))

    onStep('empty page, HEAD and unsupported methods')
    const missing = randomUUID()
    assert.equal(
      (
        await query(
          client,
          'SELECT 1 FROM p32.users WHERE username ILIKE $1 OR display_name ILIKE $1 LIMIT 1',
          [`%${missing}%`],
        )
      ).rows.length,
      0,
    )
    const empty = await send(`/api/v1/admin/users?q=${missing}`)
    assert.equal(empty.status, 200)
    assert.deepEqual(empty.body, { users: [], nextCursor: null })
    const head = await send(undefined, { method: 'HEAD' })
    publicHeaders(head)
    assert.equal(head.status, 200)
    assert.equal(head.body, null)
    const beforeMethods = runtimeCalls
    failure(await send(undefined, { method: 'POST' }), 403, 'ORIGIN_NOT_ALLOWED')
    failure(
      await send(undefined, { method: 'POST', origin: config.webOrigin }),
      404,
      'NOT_FOUND',
    )
    assert.equal(runtimeCalls, beforeMethods)

    onStep('real worker SQL error becomes safe HTTP 500 without retry')
    phase = 'query-error'
    const beforeFailure = runtimeCalls
    const broken = await send()
    failure(broken, 500, 'INTERNAL_ERROR')
    assert.equal(runtimeCalls, beforeFailure + 1)
    assert.equal(logs.length, 1)
    assert.deepEqual(logs[0], [
      'P32 API request failed',
      { code: 'INTERNAL_ERROR', request_id: broken.body.request_id },
    ])
    phase = 'normal'

    const rolesPath = (userId) => `/api/v1/admin/users/${userId}/roles`
    onStep('HTTP role-read guards before account lookup')
    const beforeRolesGuards = runtimeCalls
    const targetPath = rolesPath(student.user_id)
    failure(await send(targetPath, { cookie: null }), 401, 'AUTH_REQUIRED')
    failure(await send(targetPath, { cookie: cookies.student }), 403, 'FORBIDDEN')
    failure(await send(rolesPath('invalid')), 400, 'INVALID_USER_ROLES_INPUT')
    failure(
      await send(`${targetPath}?role=system_admin`),
      400,
      'INVALID_USER_ROLES_INPUT',
    )
    assert.equal(runtimeCalls, beforeRolesGuards)

    onStep('admin reads the selected accounts and assigned roles')
    for (const target of [admin, student]) {
      const assignments = await query(
        client,
        `SELECT r.role_code AS "roleCode", r.role_name AS "roleName"
         FROM p32.user_roles AS ur JOIN p32.roles AS r ON r.role_code = ur.role_code
         WHERE ur.user_id = $1::uuid ORDER BY ur.role_code`,
        [target.user_id],
      )
      const result = await send(rolesPath(target.user_id.toUpperCase()))
      publicHeaders(result)
      assert.equal(result.status, 200)
      assert.deepEqual(result.body, { user: dto(target), roles: assignments.rows })
    }
    assert.equal(runtimeCalls, beforeRolesGuards + 2)
    assert.equal(
      (
        await query(client, 'SELECT 1 FROM p32.users WHERE user_id = $1::uuid', [
          missing,
        ])
      ).rows.length,
      0,
    )
    failure(await send(rolesPath(missing)), 404, 'USER_NOT_FOUND')

    onStep('role-read SQL error becomes safe HTTP 500 without retry')
    phase = 'query-error'
    const beforeRolesFailure = runtimeCalls
    const beforeRolesLogs = logs.length
    const brokenRoles = await send(targetPath)
    failure(brokenRoles, 500, 'INTERNAL_ERROR')
    assert.equal(runtimeCalls, beforeRolesFailure + 1)
    assert.equal(logs.length, beforeRolesLogs + 1)
    assert.deepEqual(logs.at(-1), [
      'P32 API request failed',
      { code: 'INTERNAL_ERROR', request_id: brokenRoles.body.request_id },
    ])
    phase = 'normal'

    onStep('revoked temporary session cannot search or read roles again')
    assert.equal(await sessionRepository.revokeSession(sessions.admin), true)
    const beforeRevoked = runtimeCalls
    failure(await send(), 401, 'AUTH_REQUIRED')
    failure(await send(targetPath), 401, 'AUTH_REQUIRED')
    assert.equal(runtimeCalls, beforeRevoked)

    onStep('HTTP shutdown and temporary session rollback')
    await closeServer(server)
    server = null
    await query(client, 'ROLLBACK')
    transactionOpen = false
    assert.deepEqual(await readDemos(), beforeUsers)
    assert.deepEqual(await readSessions(), beforeSessions)
    assert.equal(
      (
        await query(
          client,
          'SELECT count(*)::integer AS count FROM p32.auth_sessions WHERE session_id = ANY($1::uuid[])',
          [sessionIds],
        )
      ).rows[0].count,
      0,
    )
  } catch (error) {
    primaryFailure = error
    throw error
  } finally {
    let cleanupFailure
    try {
      await closeServer(server)
    } catch (error) {
      cleanupFailure = error
    }
    if (client) {
      try {
        if (transactionOpen) await query(client, 'ROLLBACK')
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
    await checkUserSearchHttp(pool, (name) => {
      stage = name
    })
    console.log(
      'User search HTTP/database checks passed; temporary sessions rolled back.',
    )
    console.log(
      'User roles HTTP/database checks passed; temporary sessions rolled back.',
    )
  } catch (error) {
    const code =
      typeof error?.code === 'string' &&
      error.code.length === 5 &&
      /^[0-9A-Z]{5}$/.test(error.code)
        ? error.code
        : 'CHECK_FAILED'
    console.error(`User search HTTP check failed: ${stage} (${code})`)
    process.exitCode = 1
  } finally {
    if (pool) await pool.end()
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await main()
