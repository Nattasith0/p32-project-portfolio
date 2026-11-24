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
import { createRoleRepository } from '../src/modules/roles/roles.repository.js'
import { createRoleService } from '../src/modules/roles/roles.service.js'
import { createRoleChangeRepository } from '../src/modules/roles/role-change.repository.js'
import { createRoleChangeRuntimeRepository } from '../src/modules/roles/role-change.runtime.repository.js'
import { createRoleChangeService } from '../src/modules/roles/role-change.service.js'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const query = (client, text, values) =>
  client.query({ text, values, query_timeout: 10000 })

async function verifyTarget(client) {
  const row = (
    await query(
      client,
      `SELECT current_user AS db_user,
    current_database() AS db_name, current_setting('is_superuser')::boolean AS is_superuser,
    host(inet_server_addr()) AS address`,
    )
  ).rows[0]
  assert.equal(row.db_user, 'p32_app')
  assert.equal(row.db_name, 'p32_dev')
  assert.equal(row.is_superuser, false)
  assert.ok(['127.0.0.1', '::1'].includes(row.address))
}

const readRoleState = async (client) => ({
  roles: (await query(client, 'SELECT * FROM p32.user_roles ORDER BY user_id, role_code'))
    .rows,
  audit: (await query(client, 'SELECT * FROM p32.user_role_audit ORDER BY audit_id'))
    .rows,
})
const readSessions = async (client) =>
  (await query(client, 'SELECT * FROM p32.auth_sessions ORDER BY session_id')).rows

async function closeServer(server) {
  if (!server?.listening) return
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  )
}

// SQL ที่เปลี่ยนบทบาทอยู่ใน transaction ทดสอบที่จะ ROLLBACK
// runtime ของจริงใช้ connection แยกเฉพาะ no-op ที่ตรวจผลก่อนยอม COMMIT
export async function checkRoleChangeHttp(pool, onStep = () => {}) {
  let client
  let server
  let transactionOpen = false
  const sessionIds = []
  const requestIds = []
  const logs = []
  let runtimeCalls = 0
  let phase = 'runtime-no-op'

  try {
    onStep('database target and demo guards')
    client = await pool.connect()
    client.on('error', () => {})
    await verifyTarget(client)
    const users = (
      await query(
        client,
        `SELECT user_id, username, is_active,
      email_verified_at IS NOT NULL AS verified FROM p32.users
      WHERE username IN ('admin_demo','student_demo')`,
      )
    ).rows
    assert.equal(users.length, 2)
    const admin = users.find((row) => row.username === 'admin_demo')
    const student = users.find((row) => row.username === 'student_demo')
    assert.ok(admin?.is_active && admin.verified)
    assert.ok(student?.is_active && student.verified)
    const beforeRoles = await readRoleState(client)
    const beforeSessions = await readSessions(client)
    assert.ok(
      beforeRoles.roles.some(
        (row) => row.user_id === admin.user_id && row.role_code === 'system_admin',
      ),
    )
    assert.ok(
      beforeRoles.roles.some(
        (row) => row.user_id === student.user_id && row.role_code === 'student',
      ),
    )
    assert.ok(
      !beforeRoles.roles.some(
        (row) =>
          row.user_id === student.user_id &&
          ['advisor', 'course_manager', 'system_admin'].includes(row.role_code),
      ),
    )
    const adminCount = (
      await query(
        client,
        `SELECT count(*)::integer AS count
      FROM p32.users u JOIN p32.user_roles ur ON ur.user_id = u.user_id
      WHERE ur.role_code = 'system_admin' AND u.is_active = true
        AND u.email_verified_at IS NOT NULL`,
      )
    ).rows[0].count
    assert.equal(
      adminCount,
      1,
      'This development fixture requires one ready administrator',
    )
    const missingUserId = randomUUID()
    assert.equal(
      (
        await query(
          client,
          'SELECT count(*)::integer AS count FROM p32.users WHERE user_id = $1',
          [missingUserId],
        )
      ).rows[0].count,
      0,
    )

    const config = readAuthConfig({
      NODE_ENV: 'test',
      P32_WEB_ORIGIN: 'http://127.0.0.1',
      P32_JWT_SECRET_HEX: randomBytes(32).toString('hex'),
      P32_CSRF_SECRET_HEX: randomBytes(32).toString('hex'),
    })
    const database = { query: (text, values) => query(client, text, values) }
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
    const authorizationService = createAuthorizationService({
      authorizationRepository: createAuthorizationRepository(database),
    })
    const roleService = createRoleService({
      roleRepository: createRoleRepository(database),
    })
    const rollbackService = createRoleChangeService({
      roleChangeRepository: createRoleChangeRepository(database),
    })

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
          async query(config) {
            if (config.text.includes('FROM p32.change_user_role')) {
              runtimeCalls += 1
              assert.equal(phase, 'runtime-no-op')
              assert.deepEqual(config.values.slice(0, 4), [
                admin.user_id,
                student.user_id,
                'student',
                'assign',
              ])
              const lock = await query(
                worker,
                'SELECT pg_try_advisory_xact_lock(32,1) AS acquired',
              )
              assert.equal(lock.rows[0].acquired, true)
              assert.deepEqual(await readRoleState(worker), beforeRoles)
              const result = await worker.query(config)
              assert.deepEqual(result.rows, [{ changed: false, audit_id: null }])
              // หยุดก่อน COMMIT หาก supposed no-op เปลี่ยน role หรือ audit
              assert.deepEqual(await readRoleState(worker), beforeRoles)
              return result
            }
            return worker.query(config)
          },
        }
      },
    }
    const runtimeService = createRoleChangeService({
      roleChangeRepository: createRoleChangeRuntimeRepository(guardedPool),
    })
    const roleChangeService = {
      changeUserRole(context) {
        return (
          phase === 'runtime-no-op' ? runtimeService : rollbackService
        ).changeUserRole(context)
      },
    }
    const app = createApp({
      userSearchService: {
        async searchUsers() {
          assert.fail('Unexpected user search in role change HTTP checks')
        },
      },
      webOrigin: config.webOrigin,
      requireSession,
      authorizationService,
      roleService,
      roleChangeService,
      authService: {
        async authenticateCredentials() {
          assert.fail('Credentials are checked separately by check-auth-http.js')
        },
      },
      jwtService,
      sessionService,
      sessionRepository,
      sessionCookie,
      loginCsrfProtection: createLoginCsrfProtection({ secretHex: config.csrfSecretHex }),
      loginCsrfCookie: createLoginCsrfCookie(config.cookie.options),
      logger: {
        error(...args) {
          logs.push(args)
        },
      },
    })

    onStep('rollback transaction and temporary sessions')
    await query(client, 'BEGIN ISOLATION LEVEL READ COMMITTED')
    transactionOpen = true
    await query(client, "SET LOCAL statement_timeout = '5s'")
    await query(client, "SET LOCAL lock_timeout = '2s'")
    await query(client, "SET LOCAL idle_in_transaction_session_timeout = '15s'")
    const identities = {}
    for (const user of [admin, student]) {
      const session = await sessionService.startSession({ userId: user.user_id })
      sessionIds.push(session.sessionId)
      identities[user.username] = {
        cookie: `${config.cookie.name}=${await jwtService.signSession(session)}`,
        csrf: await sessionService.getCsrfToken(session),
      }
      assert.equal(typeof identities[user.username].csrf, 'string')
    }
    server = app.listen(0, '127.0.0.1')
    await once(server, 'listening')
    const base = `http://127.0.0.1:${server.address().port}`
    const defaultBody = {
      targetUserId: student.user_id,
      roleCode: 'student',
      action: 'assign',
      reason: 'ตรวจ HTTP แบบไม่เปลี่ยนบทบาท',
    }
    async function send({
      actor = 'admin_demo',
      origin = config.webOrigin,
      csrfToken,
      cookieHeader,
      body = defaultBody,
      raw,
      contentType = 'application/json',
      headers = {},
      method = 'POST',
      path = '/api/v1/admin/role-changes',
    } = {}) {
      const identity = identities[actor]
      const requestHeaders = { ...headers }
      if (origin !== null) requestHeaders.Origin = origin
      const cookie = cookieHeader === undefined ? identity?.cookie : cookieHeader
      if (cookie != null) requestHeaders.Cookie = cookie
      const csrf = csrfToken === undefined ? identity?.csrf : csrfToken
      if (csrf != null) requestHeaders['X-CSRF-Token'] = csrf
      if (contentType !== null) requestHeaders['Content-Type'] = contentType
      const response = await fetch(base + path, {
        method,
        headers: requestHeaders,
        body:
          method === 'GET' ? undefined : raw === undefined ? JSON.stringify(body) : raw,
        signal: AbortSignal.timeout(10000),
      })
      const result = { response, body: await response.json() }
      const id = response.headers.get('x-request-id')
      assert.match(id, UUID)
      requestIds.push(id)
      assert.equal(response.headers.get('cache-control'), 'no-store')
      assert.equal(response.headers.get('set-cookie'), null)
      assert.equal(response.headers.get('x-powered-by'), null)
      return result
    }
    const reject = (result, status, code) => {
      assert.equal(result.response.status, status)
      assert.equal(result.body.code, code)
      assert.deepEqual(Object.keys(result.body).sort(), ['code', 'message', 'request_id'])
      assert.equal(result.body.request_id, result.response.headers.get('x-request-id'))
    }
    const success = (result, changed) => {
      assert.equal(result.response.status, 200)
      assert.deepEqual(Object.keys(result.body).sort(), ['auditId', 'changed'])
      assert.equal(result.body.changed, changed)
      if (changed) assert.match(result.body.auditId, UUID)
      else assert.equal(result.body.auditId, null)
    }
    const change = (roleCode, action = 'assign') => ({
      ...defaultBody,
      roleCode,
      action,
      reason: 'ตรวจเพิ่ม–ถอนบทบาทผ่าน HTTP แล้ว rollback',
    })

    onStep('Origin/session/role/CSRF guards')
    reject(await send({ origin: null }), 403, 'ORIGIN_NOT_ALLOWED')
    reject(await send({ origin: 'https://attacker.example' }), 403, 'ORIGIN_NOT_ALLOWED')
    reject(await send({ cookieHeader: null }), 401, 'AUTH_REQUIRED')
    reject(
      await send({ cookieHeader: `${config.cookie.name}=malformed` }),
      401,
      'AUTH_REQUIRED',
    )
    reject(
      await send({
        actor: 'student_demo',
        headers: { 'X-Role': 'system_admin', 'X-User-Id': admin.user_id },
      }),
      403,
      'FORBIDDEN',
    )
    reject(await send({ csrfToken: null }), 403, 'CSRF_INVALID')
    reject(await send({ csrfToken: identities.student_demo.csrf }), 403, 'CSRF_INVALID')
    assert.equal(runtimeCalls, 0)

    onStep('HTTP no-op through real runtime transaction on a separate connection')
    const noop = await send()
    success(noop, false)
    assert.equal(runtimeCalls, 1)
    assert.deepEqual(await readRoleState(client), beforeRoles)
    phase = 'rollback-flow'

    onStep('JSON and body validation before SQL')
    reject(await send({ contentType: 'text/plain' }), 415, 'UNSUPPORTED_MEDIA_TYPE')
    reject(await send({ raw: '{' }), 400, 'INVALID_JSON')
    reject(
      await send({ body: { ...defaultBody, reason: 'x'.repeat(17 * 1024) } }),
      413,
      'PAYLOAD_TOO_LARGE',
    )
    reject(
      await send({ body: { ...defaultBody, actorUserId: admin.user_id } }),
      400,
      'INVALID_ROLE_CHANGE_INPUT',
    )
    reject(
      await send({ body: { ...defaultBody, requestId: randomUUID() } }),
      400,
      'INVALID_ROLE_CHANGE_INPUT',
    )
    assert.deepEqual(await readRoleState(client), beforeRoles)

    const expectedEvents = []
    async function apply(roleCode, action = 'assign', options = {}) {
      const body = change(roleCode, action)
      const result = await send({ body, ...options })
      success(result, true)
      expectedEvents.push({
        auditId: result.body.auditId,
        roleCode,
        action,
        reason: body.reason,
        requestId: result.response.headers.get('x-request-id'),
      })
      return result
    }
    onStep('assign, no-op and multiple roles with server-controlled actor')
    const assigned = await apply('advisor', 'assign', {
      headers: { 'X-Request-Id': student.user_id, 'X-User-Id': student.user_id },
    })
    assert.notEqual(assigned.response.headers.get('x-request-id'), student.user_id)
    const afterAssign = await readRoleState(client)
    success(await send({ body: change('advisor') }), false)
    assert.deepEqual(await readRoleState(client), afterAssign)
    await apply('course_manager')
    const studentRoles = (await readRoleState(client)).roles
      .filter((row) => row.user_id === student.user_id)
      .map((row) => row.role_code)
      .sort()
    assert.deepEqual(studentRoles, ['advisor', 'course_manager', 'student'])
    reject(
      await send({ actor: 'student_demo', body: change('system_admin') }),
      403,
      'FORBIDDEN',
    )

    onStep('revoke and repeated revoke')
    await apply('course_manager', 'revoke')
    await apply('advisor', 'revoke')
    const afterRevoke = await readRoleState(client)
    success(await send({ body: change('advisor', 'revoke') }), false)
    assert.deepEqual(await readRoleState(client), afterRevoke)
    assert.deepEqual(afterRevoke.roles, beforeRoles.roles)
    assert.equal(afterRevoke.audit.length, beforeRoles.audit.length + 4)
    for (const event of expectedEvents) {
      const row = afterRevoke.audit.find((value) => value.audit_id === event.auditId)
      assert.equal(row.target_user_id, student.user_id)
      assert.equal(row.actor_user_id, admin.user_id)
      assert.equal(row.role_code, event.roleCode)
      assert.equal(row.action, event.action)
      assert.equal(row.reason, event.reason)
      assert.equal(row.request_id, event.requestId)
    }

    onStep('database domain errors with savepoint recovery')
    await query(client, 'SAVEPOINT before_missing_target')
    reject(
      await send({ body: { ...change('advisor'), targetUserId: missingUserId } }),
      404,
      'ROLE_TARGET_NOT_FOUND',
    )
    await query(client, 'ROLLBACK TO SAVEPOINT before_missing_target')
    await query(client, 'RELEASE SAVEPOINT before_missing_target')
    await query(client, 'SAVEPOINT before_last_admin')
    reject(
      await send({
        body: { ...change('system_admin', 'revoke'), targetUserId: admin.user_id },
      }),
      409,
      'LAST_SYSTEM_ADMIN',
    )
    await query(client, 'ROLLBACK TO SAVEPOINT before_last_admin')
    await query(client, 'RELEASE SAVEPOINT before_last_admin')
    assert.deepEqual(await readRoleState(client), afterRevoke)

    onStep('existing current-user and role catalog endpoints')
    const me = await send({ method: 'GET', path: '/api/v1/auth/me' })
    assert.equal(me.response.status, 200)
    assert.equal(me.body.user.userId, admin.user_id)
    const catalog = await send({ method: 'GET', path: '/api/v1/admin/roles' })
    assert.equal(catalog.response.status, 200)
    assert.equal(catalog.body.roles.length, 6)
    assert.deepEqual(logs, [])

    onStep('HTTP shutdown and rollback')
    await closeServer(server)
    server = null
    await query(client, 'ROLLBACK')
    transactionOpen = false
    onStep('sessions, roles and audit cleanup')
    assert.deepEqual(await readRoleState(client), beforeRoles)
    assert.deepEqual(await readSessions(client), beforeSessions)
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
    assert.equal(
      (
        await query(
          client,
          'SELECT count(*)::integer AS count FROM p32.user_role_audit WHERE request_id = ANY($1::uuid[])',
          [requestIds],
        )
      ).rows[0].count,
      0,
    )
  } finally {
    try {
      await closeServer(server)
    } finally {
      if (client) {
        try {
          if (transactionOpen) await query(client, 'ROLLBACK')
        } finally {
          client.release(true)
        }
      }
    }
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
    await checkRoleChangeHttp(pool, (name) => {
      stage = name
    })
    console.log(
      'Role change HTTP/database checks passed; test sessions, roles and audit rolled back.',
    )
  } catch (error) {
    console.error(
      `Role change HTTP check failed: ${stage} (${error.code ?? 'CHECK_FAILED'})`,
    )
    process.exitCode = 1
  } finally {
    if (pool) await pool.end()
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await main()
