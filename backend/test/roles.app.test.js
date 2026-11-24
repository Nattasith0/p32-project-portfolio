import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request as httpRequest } from 'node:http'
import { createRoleRepository } from '../src/modules/roles/roles.repository.js'
import { createRoleService } from '../src/modules/roles/roles.service.js'
import { createRoleChangeService } from '../src/modules/roles/role-change.service.js'
import { createUserSearchService } from '../src/modules/users/user-search.service.js'
import { createUserRolesService } from '../src/modules/users/user-roles.service.js'
import { createAuthorizationRepository } from '../src/modules/authorization/authorization.repository.js'
import { createAuthorizationService } from '../src/modules/authorization/authorization.service.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'

import { createApp } from '../src/app.js'
import { readAuthConfig } from '../src/config/auth.config.js'
import { createJwtService } from '../src/security/jwt.js'
import { createSessionAuthService } from '../src/modules/auth/session-auth.service.js'
import { createLoginCsrfProtection } from '../src/security/login-csrf.js'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'

// ใช้ app/JWT/cookie/session middleware จริง แต่จำลอง query executor และ session rows
// ไม่อ่าน .env และไม่เชื่อมฐานข้อมูลจริง
const config = readAuthConfig({
  NODE_ENV: 'test',
  P32_WEB_ORIGIN: 'http://localhost:5173',
  P32_JWT_SECRET_HEX: '55'.repeat(32),
  P32_CSRF_SECRET_HEX: '66'.repeat(32),
})
const CSRF_TOKEN = 'a'.repeat(43)
const AUDIT_ID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
const FIXED_TIME = Date.parse('2026-11-03T05:00:00.987Z')

const actors = {
  admin: {
    userId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    sessionId: '11111111-1111-4111-8111-111111111111',
  },
  student: {
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    sessionId: '22222222-2222-4222-8222-222222222222',
  },
  faculty: {
    userId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    sessionId: '33333333-3333-4333-8333-333333333333',
  },
}
const catalog = [
  { role_code: 'advisor', role_name: 'อาจารย์ที่ปรึกษา' },
  { role_code: 'course_manager', role_name: 'ผู้ดูแลวิชา' },
  { role_code: 'examiner', role_name: 'กรรมการสอบ' },
  { role_code: 'portfolio_viewer', role_name: 'นักศึกษาผู้ชม Portfolio ภายใน' },
  { role_code: 'student', role_name: 'นักศึกษาในโครงงาน' },
  { role_code: 'system_admin', role_name: 'ผู้ดูแลระบบ' },
]
const expectedRoles = catalog.map((row) => ({
  roleCode: row.role_code,
  roleName: row.role_name,
}))

async function fixture(t, options = {}) {
  const stats = {
    roleLookups: [],
    catalogReads: 0,
    authCalls: 0,
    sessionLookups: [],
    csrfCalls: 0,
    roleChanges: [],
    userSearches: [],
    userRolesLookups: [],
    logs: [],
  }
  let currentTime = FIXED_TIME
  const expiresAt = new Date((Math.floor(FIXED_TIME / 1000) + 1800) * 1000)
  const jwtService = createJwtService({
    secretHex: config.jwtSecretHex,
    now: () => currentTime,
  })
  const tokens = {}
  for (const [name, actor] of Object.entries(actors)) {
    tokens[name] = await jwtService.signSession({ ...actor, expiresAt })
  }
  const cookie = (actor) => `${config.cookie.name}=${tokens[actor]}`
  const database = {
    async query(sql, values) {
      if (sql.includes('FROM p32.user_roles')) {
        stats.roleLookups.push(values[0])
        if (options.roleError) throw options.roleError
        const roles =
          values[0] === actors.admin.userId
            ? options.adminRevoked
              ? []
              : ['system_admin']
            : values[0] === actors.student.userId
              ? ['student']
              : ['advisor', 'course_manager']
        return { rows: roles.map((role_code) => ({ role_code })) }
      }
      assert.match(sql, /FROM p32\.roles/)
      stats.catalogReads += 1
      if (options.catalogError) throw options.catalogError
      return {
        rows:
          options.catalogRows ??
          catalog.map((row) => ({ ...row, private_field: 'PRIVATE_TEST_DATA' })),
      }
    },
  }
  const authorizationService = createAuthorizationService({
    authorizationRepository: createAuthorizationRepository(database),
  })
  const roleService =
    options.roleService ??
    createRoleService({ roleRepository: createRoleRepository(database) })
  const sessionCookie = createSessionCookie(config.cookie)
  const sessionRepository = {
    async findActiveSession(context) {
      stats.sessionLookups.push(context)
      if (options.rejectSession || expiresAt.getTime() <= currentTime) return null
      const actor = Object.entries(actors).find(
        ([, value]) =>
          value.userId === context.userId && value.sessionId === context.sessionId,
      )
      if (!actor) return null
      return {
        session_id: context.sessionId,
        user_id: context.userId,
        expires_at: expiresAt,
        username: `${actor[0]}_demo`,
        display_name: 'ผู้ใช้ทดสอบ',
        csrf_token_hash: 'a'.repeat(64),
      }
    },
    async revokeSession() {
      assert.fail('Role catalog tests must not revoke sessions')
    },
  }
  const sessionAuthService = createSessionAuthService({ jwtService, sessionRepository })
  const requireSession = createRequireSession({
    sessionCookie,
    sessionAuthService: {
      async authenticateSessionToken(token) {
        stats.authCalls += 1
        return sessionAuthService.authenticateSessionToken(token)
      },
    },
  })
  const dependencies = {
    webOrigin: config.webOrigin,
    requireSession,
    authorizationService,
    roleService,
    userRolesService: createUserRolesService({
      userRolesRepository: {
        async findUserRolesByUserId(targetId) {
          stats.userRolesLookups.push(targetId)
          if (options.userRolesError) throw options.userRolesError
          return options.userRolesRows ?? []
        },
      },
    }),
    userSearchService: createUserSearchService({
      userSearchRepository: {
        async searchUsers(search) {
          stats.userSearches.push(search)
          assert.equal(
            options.allowUserSearch,
            true,
            'Unexpected user search in catalog fixture',
          )
          if (options.userSearchError) throw options.userSearchError
          const source =
            options.userSearchRows ??
            Object.entries(actors).map(([name, actor]) => ({
              user_id: actor.userId,
              username: `${name}_demo`,
              display_name: 'ผู้ใช้ทดสอบ',
              is_active: true,
              email_verified: true,
              email: 'PRIVATE_TEST_DATA',
            }))
          const term = search.searchTerm.toLowerCase()
          return source
            .filter(
              (row) =>
                row.username.toLowerCase().includes(term) ||
                row.display_name.toLowerCase().includes(term),
            )
            .filter((row) => search.after === null || row.user_id > search.after)
            .sort((a, b) => a.user_id.localeCompare(b.user_id))
            .slice(0, search.limit + 1)
        },
      },
    }),
    jwtService,
    roleChangeService: createRoleChangeService({
      roleChangeRepository: {
        async changeUserRole(context) {
          stats.roleChanges.push(context)
          assert.equal(
            options.allowRoleChanges,
            true,
            'Unexpected role mutation in catalog fixture',
          )
          if (options.roleChangeError) throw options.roleChangeError
          return options.roleChangeResult ?? { changed: true, auditId: AUDIT_ID }
        },
      },
    }),
    sessionRepository,
    sessionCookie,
    authService: {
      async authenticateCredentials() {
        assert.fail('Role catalog tests must not verify passwords')
      },
    },
    sessionService: {
      async startSession() {
        assert.fail('Role catalog tests must not create sessions')
      },
      async getCsrfToken() {
        stats.csrfCalls += 1
        assert.equal(
          options.allowRoleChanges,
          true,
          'Unexpected authenticated CSRF request in catalog fixture',
        )
        return CSRF_TOKEN
      },
    },
    loginCsrfProtection: createLoginCsrfProtection({
      secretHex: config.csrfSecretHex,
      now: () => currentTime,
    }),
    loginCsrfCookie: createLoginCsrfCookie(config.cookie.options),
    logger: {
      error(...args) {
        stats.logs.push(args)
      },
    },
  }
  const app = createApp(dependencies)
  const server = app.listen(0, '127.0.0.1')
  t.after(
    () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  )
  await once(server, 'listening')
  const baseUrl = `http://127.0.0.1:${server.address().port}`

  function send({
    actor = 'admin',
    cookieHeader,
    query = '',
    headers = {},
    method = 'GET',
    path = '/api/v1/admin/roles',
    body,
  } = {}) {
    const requestHeaders = { ...headers }
    const payload = body === undefined ? undefined : JSON.stringify(body)
    if (payload !== undefined) {
      requestHeaders['Content-Type'] = 'application/json'
      requestHeaders['Content-Length'] = Buffer.byteLength(payload)
    }
    const cookieValue = cookieHeader === undefined ? cookie(actor) : cookieHeader
    if (cookieValue !== null) requestHeaders.Cookie = cookieValue
    return new Promise((resolve, reject) => {
      const request = httpRequest(
        baseUrl + path + query,
        { method, headers: requestHeaders, agent: false, timeout: 5000 },
        (response) => {
          const chunks = []
          response.on('error', reject)
          response.on('data', (chunk) => chunks.push(chunk))
          response.on('end', () => {
            try {
              const text = Buffer.concat(chunks).toString('utf8')
              resolve({
                status: response.statusCode,
                headers: response.headers,
                body: text ? JSON.parse(text) : null,
              })
            } catch (error) {
              reject(error)
            }
          })
        },
      )
      request.on('error', reject)
      request.on('timeout', () => request.destroy(new Error('Test request timed out')))
      request.end(payload)
    })
  }
  return {
    send,
    stats,
    dependencies,
    tokens,
    advance(milliseconds) {
      currentTime += milliseconds
    },
  }
}

function assertFailure(result, status, code) {
  assert.equal(result.status, status)
  assert.equal(result.body.code, code)
  assert.equal(result.body.request_id, result.headers['x-request-id'])
  assert.equal(result.headers['cache-control'], 'no-store')
  assert.equal(result.headers['set-cookie'], undefined)
  assert.deepEqual(Object.keys(result.body).sort(), ['code', 'message', 'request_id'])
}

test('full app: system admin reads the selected inactive account and its public roles', async (t) => {
  const target = actors.faculty.userId
  const account = {
    user_id: target,
    username: 'faculty_demo',
    display_name: 'อาจารย์ทดสอบ',
    is_active: false,
    email_verified: false,
    email: 'PRIVATE_TEST_DATA',
  }
  const { send, stats } = await fixture(t, {
    userRolesRows: [
      { ...account, role_code: 'advisor', role_name: 'อาจารย์ที่ปรึกษา' },
      { ...account, role_code: 'course_manager', role_name: 'ผู้ดูแลวิชา' },
    ],
  })
  const result = await send({
    path: `/api/v1/admin/users/${target.toUpperCase()}/roles`,
  })
  assert.equal(result.status, 200)
  assert.equal(result.headers['cache-control'], 'no-store')
  assert.ok(result.headers['x-request-id'])
  assert.deepEqual(result.body, {
    user: {
      userId: target,
      username: 'faculty_demo',
      displayName: 'อาจารย์ทดสอบ',
      isActive: false,
      emailVerified: false,
    },
    roles: [
      { roleCode: 'advisor', roleName: 'อาจารย์ที่ปรึกษา' },
      { roleCode: 'course_manager', roleName: 'ผู้ดูแลวิชา' },
    ],
  })
  assert.deepEqual(stats.roleLookups, [actors.admin.userId])
  assert.deepEqual(stats.userRolesLookups, [target])
})

test('full app: session and role checks precede validation and account access', async (t) => {
  const { send, stats } = await fixture(t)
  const path = '/api/v1/admin/users/invalid/roles'
  assertFailure(await send({ path, cookieHeader: null }), 401, 'AUTH_REQUIRED')
  for (const actor of ['student', 'faculty']) {
    assertFailure(await send({ path, actor }), 403, 'FORBIDDEN')
  }
  assertFailure(await send({ path }), 400, 'INVALID_USER_ROLES_INPUT')
  assertFailure(
    await send({
      path: `/api/v1/admin/users/${actors.faculty.userId}/roles`,
      query: '?role=system_admin',
    }),
    400,
    'INVALID_USER_ROLES_INPUT',
  )
  assert.deepEqual(stats.userRolesLookups, [])
})

test('full app: an existing account without roles, a missing account and a database failure are distinct', async (t) => {
  const target = actors.faculty.userId
  const path = `/api/v1/admin/users/${target}/roles`
  const options = {
    userRolesRows: [
      {
        user_id: target,
        username: 'faculty_demo',
        display_name: 'อาจารย์ทดสอบ',
        is_active: true,
        email_verified: true,
        role_code: null,
        role_name: null,
      },
    ],
  }
  const { send, stats } = await fixture(t, options)
  const empty = await send({ path })
  assert.equal(empty.status, 200)
  assert.deepEqual(empty.body.roles, [])
  options.userRolesRows = []
  assertFailure(await send({ path }), 404, 'USER_NOT_FOUND')
  options.userRolesError = new Error('PRIVATE_TEST_DATABASE_DETAILS')
  const failed = await send({ path })
  assertFailure(failed, 500, 'INTERNAL_ERROR')
  assert.ok(
    !JSON.stringify([failed.body, stats.logs]).includes(
      'PRIVATE_TEST_DATABASE_DETAILS',
    ),
  )
})

test('full app: admin receives ordered role metadata with only public fields', async (t) => {
  const { send, stats } = await fixture(t)
  const result = await send()
  assert.equal(result.status, 200)
  assert.deepEqual(result.body, { roles: expectedRoles })
  assert.equal(result.headers['cache-control'], 'no-store')
  assert.ok(result.headers['x-request-id'])
  assert.equal(result.headers['set-cookie'], undefined)
  assert.deepEqual(stats.roleLookups, [actors.admin.userId])
  assert.equal(stats.catalogReads, 1)
})

test('full app: student and multi-role faculty are denied before catalog lookup', async (t) => {
  const { send, stats } = await fixture(t)
  for (const actor of ['student', 'faculty'])
    assertFailure(await send({ actor }), 403, 'FORBIDDEN')
  assert.equal(stats.catalogReads, 0)
})

test('full app: missing or malformed session cookies are denied before any role query', async (t) => {
  const { send, stats } = await fixture(t)
  for (const cookieHeader of [null, 'p32_session_dev=malformed']) {
    assertFailure(await send({ cookieHeader }), 401, 'AUTH_REQUIRED')
  }
  assert.equal(stats.authCalls, 0)
  assert.equal(stats.roleLookups.length, 0)
  assert.equal(stats.catalogReads, 0)
})

test('full app: sessions rejected by authentication cannot reach role or catalog lookup', async (t) => {
  const { send, stats } = await fixture(t, { rejectSession: true })
  assertFailure(await send(), 401, 'AUTH_REQUIRED')
  assert.equal(stats.roleLookups.length, 0)
  assert.equal(stats.catalogReads, 0)
})

test('full app: client identifiers and role claims do not replace the authenticated student', async (t) => {
  const { send, stats } = await fixture(t)
  const result = await send({
    actor: 'student',
    query: `?userId=${actors.admin.userId}&allowedRoles=student&role=system_admin`,
    headers: { 'X-User-Id': actors.admin.userId, 'X-Role': 'system_admin' },
  })
  assertFailure(result, 403, 'FORBIDDEN')
  assert.deepEqual(stats.roleLookups, [actors.student.userId])
  assert.equal(stats.catalogReads, 0)
})

test('full app: role lookup errors fail before catalog lookup without leaking details', async (t) => {
  const { send, stats } = await fixture(t, {
    roleError: new Error('PRIVATE_TEST_DATA'),
  })
  const result = await send()
  assertFailure(result, 500, 'INTERNAL_ERROR')
  assert.equal(stats.catalogReads, 0)
  assert.equal(
    JSON.stringify([result.body, stats.logs]).includes('PRIVATE_TEST_DATA'),
    false,
  )
})

test('full app: catalog lookup errors and invalid rows never become successful responses', async (t) => {
  for (const options of [
    { catalogError: new Error('PRIVATE_TEST_DATA') },
    { catalogRows: [{}] },
  ]) {
    const { send, stats } = await fixture(t, options)
    const result = await send()
    assertFailure(result, 500, 'INTERNAL_ERROR')
    assert.equal(
      JSON.stringify([result.body, stats.logs]).includes('PRIVATE_TEST_DATA'),
      false,
    )
  }
})

test('full app: HEAD uses the same authentication and role policy', async (t) => {
  const { send } = await fixture(t)
  assert.equal((await send({ method: 'HEAD' })).status, 200)
  assert.equal((await send({ method: 'HEAD', actor: 'student' })).status, 403)
  const unauthenticated = await send({ method: 'HEAD', cookieHeader: null })
  assert.equal(unauthenticated.status, 401)
  assert.equal(unauthenticated.body, null)
})

test('full app: unsupported POST does not invoke catalog lookup', async (t) => {
  const { send, stats } = await fixture(t)
  assert.equal(
    (await send({ method: 'POST', headers: { Origin: 'http://localhost:5173' } }))
      .status,
    404,
  )
  assert.equal(stats.catalogReads, 0)
})

test('full app: app rejects missing role dependencies during construction', async (t) => {
  const { dependencies } = await fixture(t)
  assert.throws(
    () => createApp({ ...dependencies, authorizationService: undefined }),
    TypeError,
  )
  assert.throws(() => createApp({ ...dependencies, roleService: undefined }), TypeError)
  assert.throws(
    () => createApp({ ...dependencies, userSearchService: undefined }),
    TypeError,
  )
  assert.throws(
    () => createApp({ ...dependencies, roleChangeService: undefined }),
    TypeError,
  )
})

test('full app: health, public login challenge and current-user API remain available', async (t) => {
  const { send, stats } = await fixture(t)
  assert.equal((await send({ path: '/api/health', cookieHeader: null })).status, 200)
  const challenge = await send({ path: '/api/v1/auth/login-csrf', cookieHeader: null })
  assert.equal(challenge.status, 200)
  assert.equal(typeof challenge.body.csrfToken, 'string')
  const me = await send({ path: '/api/v1/auth/me' })
  assert.equal(me.status, 200)
  assert.equal(me.body.user.userId, actors.admin.userId)
  assert.deepEqual(Object.keys(me.body.user).sort(), [
    'displayName',
    'userId',
    'username',
  ])
  assertFailure(
    await send({ path: '/api/v1/auth/me', cookieHeader: null }),
    401,
    'AUTH_REQUIRED',
  )
  assert.equal((await send({ path: '/api/not-found' })).status, 404)
  assert.equal(stats.catalogReads, 0)
  assert.equal(stats.roleLookups.length, 0)
})

test('full app: tampered JWTs are rejected before session and role queries', async (t) => {
  const { send, stats, tokens } = await fixture(t)
  const parts = tokens.admin.split('.')
  parts[2] = (parts[2][0] === 'a' ? 'b' : 'a') + parts[2].slice(1)
  assertFailure(
    await send({ cookieHeader: `${config.cookie.name}=${parts.join('.')}` }),
    401,
    'AUTH_REQUIRED',
  )
  assert.equal(stats.sessionLookups.length, 0)
  assert.equal(stats.roleLookups.length, 0)
  assert.equal(stats.catalogReads, 0)
})

test('full app: expired JWTs are rejected before session and role queries', async (t) => {
  const { send, stats, advance } = await fixture(t)
  advance(1800 * 1000)
  assertFailure(await send(), 401, 'AUTH_REQUIRED')
  assert.equal(stats.sessionLookups.length, 0)
  assert.equal(stats.roleLookups.length, 0)
  assert.equal(stats.catalogReads, 0)
})

test('full app: Origin guard rejects state-changing requests before authentication', async (t) => {
  const { send, stats } = await fixture(t)
  assertFailure(await send({ method: 'POST' }), 403, 'ORIGIN_NOT_ALLOWED')
  assertFailure(
    await send({ method: 'POST', headers: { Origin: 'https://attacker.example' } }),
    403,
    'ORIGIN_NOT_ALLOWED',
  )
  assert.equal(stats.authCalls, 0)
  assert.equal(stats.sessionLookups.length, 0)
  assert.equal(stats.roleLookups.length, 0)
  assert.equal(stats.catalogReads, 0)
})

// ตรวจการ mount ใน createApp จริง ใช้ JWT/session จริงกับ role/session rows จำลอง
// CSRF service และ mutation repository เป็น fixture; crypto/runtime chain ครบอยู่ใน role-change.routes.test.js
function mutationRequest(overrides = {}) {
  return {
    method: 'POST',
    path: '/api/v1/admin/role-changes',
    headers: { Origin: config.webOrigin, 'X-CSRF-Token': CSRF_TOKEN },
    body: {
      targetUserId: actors.student.userId,
      roleCode: 'advisor',
      action: 'assign',
      reason: 'มอบหมายหน้าที่',
    },
    ...overrides,
  }
}

test('full app: role-change endpoint reaches the injected service using server identity and request ID', async (t) => {
  const { send, stats } = await fixture(t, { allowRoleChanges: true })
  const result = await send(
    mutationRequest({
      query: '?actorUserId=' + actors.student.userId,
      headers: {
        Origin: config.webOrigin,
        'X-CSRF-Token': CSRF_TOKEN,
        'X-User-Id': actors.student.userId,
        'X-Request-Id': actors.student.userId,
      },
    }),
  )
  assert.equal(result.status, 200)
  assert.deepEqual(result.body, { changed: true, auditId: AUDIT_ID })
  assert.equal(result.headers['cache-control'], 'no-store')
  assert.equal(result.headers['set-cookie'], undefined)
  assert.notEqual(result.headers['x-request-id'], actors.student.userId)
  assert.deepEqual(stats.roleChanges, [
    {
      actorUserId: actors.admin.userId,
      requestId: result.headers['x-request-id'],
      targetUserId: actors.student.userId,
      roleCode: 'advisor',
      action: 'assign',
      reason: 'มอบหมายหน้าที่',
    },
  ])
  assert.equal(stats.catalogReads, 0)
  assert.equal(stats.csrfCalls, 1)
})

test('full app: role-change no-op and revoke use the same endpoint and response shape', async (t) => {
  const { send, stats } = await fixture(t, {
    allowRoleChanges: true,
    roleChangeResult: { changed: false, auditId: null },
  })
  const request = mutationRequest()
  request.body.action = 'revoke'
  const result = await send(request)
  assert.equal(result.status, 200)
  assert.deepEqual(result.body, { changed: false, auditId: null })
  assert.equal(stats.roleChanges[0].action, 'revoke')
})

test('full app: role-change Origin and session guards run before mutation', async (t) => {
  const { send, stats } = await fixture(t, { allowRoleChanges: true })
  assertFailure(await send(mutationRequest({ headers: {} })), 403, 'ORIGIN_NOT_ALLOWED')
  assertFailure(
    await send(mutationRequest({ headers: { Origin: 'https://attacker.example' } })),
    403,
    'ORIGIN_NOT_ALLOWED',
  )
  assert.equal(stats.authCalls, 0)
  assertFailure(
    await send(mutationRequest({ cookieHeader: null })),
    401,
    'AUTH_REQUIRED',
  )
  assert.equal(stats.roleChanges.length, 0)
})

test('full app: students and multi-role faculty cannot invoke role changes', async (t) => {
  const { send, stats } = await fixture(t, { allowRoleChanges: true })
  for (const actor of ['student', 'faculty']) {
    assertFailure(await send(mutationRequest({ actor })), 403, 'FORBIDDEN')
  }
  assert.equal(stats.csrfCalls, 0)
  assert.equal(stats.roleChanges.length, 0)
})

test('full app: role-change CSRF guard rejects missing and incorrect tokens', async (t) => {
  const { send, stats } = await fixture(t, { allowRoleChanges: true })
  assertFailure(
    await send(mutationRequest({ headers: { Origin: config.webOrigin } })),
    403,
    'CSRF_INVALID',
  )
  assertFailure(
    await send(
      mutationRequest({
        headers: { Origin: config.webOrigin, 'X-CSRF-Token': 'b'.repeat(43) },
      }),
    ),
    403,
    'CSRF_INVALID',
  )
  assert.equal(stats.roleChanges.length, 0)
})

test('full app: role-change validation rejects forged body context before repository calls', async (t) => {
  const { send, stats } = await fixture(t, { allowRoleChanges: true })
  const request = mutationRequest()
  request.body.actorUserId = actors.admin.userId
  assertFailure(await send(request), 400, 'INVALID_ROLE_CHANGE_INPUT')
  assert.equal(stats.roleChanges.length, 0)
})

test('full app: role-change domain and unexpected errors use fixed safe responses', async (t) => {
  for (const [code, status, publicCode] of [
    ['P3206', 409, 'LAST_SYSTEM_ADMIN'],
    ['P3207', 409, 'ROLE_CHANGE_BUSY'],
    ['57014', 500, 'INTERNAL_ERROR'],
  ]) {
    const { send, stats } = await fixture(t, {
      allowRoleChanges: true,
      roleChangeError: Object.assign(new Error('PRIVATE_ROLE_CHANGE_DETAIL'), { code }),
    })
    const result = await send(mutationRequest())
    assertFailure(result, status, publicCode)
    assert.equal(stats.roleChanges.length, 1)
    assert.equal(
      JSON.stringify([result.body, stats.logs]).includes('PRIVATE_ROLE_CHANGE_DETAIL'),
      false,
    )
  }
})

test('full app: expired JWTs cannot reach role-change role lookup or repository', async (t) => {
  const { send, stats, advance } = await fixture(t, { allowRoleChanges: true })
  advance(1800 * 1000)
  assertFailure(await send(mutationRequest()), 401, 'AUTH_REQUIRED')
  assert.equal(stats.sessionLookups.length, 0)
  assert.equal(stats.roleLookups.length, 0)
  assert.equal(stats.roleChanges.length, 0)
})

test('full app: registered user search returns public cursor pages through real JWT/session guards', async (t) => {
  const { send, stats } = await fixture(t, { allowUserSearch: true })
  let after
  const collected = []
  for (const name of ['admin', 'student', 'faculty']) {
    const result = await send({
      path: '/api/v1/admin/users',
      query: `?q=demo&limit=1${after ? `&after=${after}` : ''}`,
    })
    assert.equal(result.status, 200)
    assert.equal(result.headers['cache-control'], 'no-store')
    assert.equal(result.headers['set-cookie'], undefined)
    assert.ok(result.headers['x-request-id'])
    assert.deepEqual(result.body.users, [
      {
        userId: actors[name].userId,
        username: `${name}_demo`,
        displayName: 'ผู้ใช้ทดสอบ',
        isActive: true,
        emailVerified: true,
      },
    ])
    assert.equal(JSON.stringify(result.body).includes('PRIVATE_TEST_DATA'), false)
    assert.equal(
      result.body.nextCursor,
      name === 'faculty' ? null : actors[name].userId,
    )
    collected.push(...result.body.users.map((user) => user.userId))
    after = result.body.nextCursor
  }
  assert.deepEqual(
    collected,
    Object.values(actors).map((actor) => actor.userId),
  )
  assert.equal(stats.userSearches.length, 3)
  const empty = await send({ path: '/api/v1/admin/users', query: '?q=missing' })
  assert.deepEqual(empty.body, { users: [], nextCursor: null })
})

test('full app: user search denies anonymous, invalid sessions and non-admin roles before searching', async (t) => {
  const { send, stats } = await fixture(t, { allowUserSearch: true })
  for (const [options, status, code] of [
    [{ cookieHeader: null }, 401, 'AUTH_REQUIRED'],
    [{ cookieHeader: `${config.cookie.name}=invalid` }, 401, 'AUTH_REQUIRED'],
    [{ actor: 'student' }, 403, 'FORBIDDEN'],
    [{ actor: 'faculty' }, 403, 'FORBIDDEN'],
  ]) {
    assertFailure(
      await send({ ...options, path: '/api/v1/admin/users', query: '?q=demo' }),
      status,
      code,
    )
  }
  assert.equal(stats.userSearches.length, 0)
})

test('full app: invalid search query fields fail before repository access', async (t) => {
  const { send, stats } = await fixture(t, { allowUserSearch: true })
  for (const query of [
    '',
    '?q=x',
    '?q=demo&limit=51',
    '?q=demo&q=student',
    '?q=demo&role=system_admin',
  ]) {
    assertFailure(
      await send({ path: '/api/v1/admin/users', query }),
      400,
      'INVALID_USER_SEARCH_INPUT',
    )
  }
  assert.equal(stats.userSearches.length, 0)
})

test('full app: user search timeout errors use the safe global error handler without retry', async (t) => {
  const { send, stats } = await fixture(t, {
    allowUserSearch: true,
    userSearchError: Object.assign(new Error('PRIVATE_SEARCH_SQL_DETAIL'), {
      code: '57014',
    }),
  })
  const result = await send({ path: '/api/v1/admin/users', query: '?q=demo' })
  assertFailure(result, 500, 'INTERNAL_ERROR')
  assert.equal(stats.userSearches.length, 1)
  assert.equal(
    JSON.stringify([result.body, stats.logs]).includes('PRIVATE_SEARCH_SQL_DETAIL'),
    false,
  )
})

test('full app: revoked admin permission and expired JWT immediately block subsequent searches', async (t) => {
  const options = { allowUserSearch: true }
  const { send, stats, advance } = await fixture(t, options)
  const search = () => send({ path: '/api/v1/admin/users', query: '?q=demo' })
  assert.equal((await search()).status, 200)
  options.adminRevoked = true
  assertFailure(await search(), 403, 'FORBIDDEN')
  const lookupsBeforeExpiry = stats.roleLookups.length
  advance(1800 * 1000)
  assertFailure(await search(), 401, 'AUTH_REQUIRED')
  assert.equal(stats.roleLookups.length, lookupsBeforeExpiry)
  assert.equal(stats.userSearches.length, 1)
})

test('full app: search HEAD is protected and unsupported paths or methods never search', async (t) => {
  const { send, stats } = await fixture(t, { allowUserSearch: true })
  const head = await send({
    path: '/api/v1/admin/users',
    query: '?q=demo',
    method: 'HEAD',
  })
  assert.equal(head.status, 200)
  assert.equal(head.body, null)
  assert.equal(
    (
      await send({
        path: '/api/v1/admin/users',
        method: 'HEAD',
        query: '?q=demo',
        actor: 'student',
      })
    ).status,
    403,
  )
  assertFailure(
    await send({ path: '/api/v1/admin/users', method: 'POST' }),
    403,
    'ORIGIN_NOT_ALLOWED',
  )
  assert.equal(
    (
      await send({
        path: '/api/v1/admin/users',
        method: 'POST',
        headers: { Origin: config.webOrigin },
      })
    ).status,
    404,
  )
  assert.equal(
    (await send({ path: '/api/v1/admin/users/unknown', query: '?q=demo' })).status,
    404,
  )
  assert.equal(stats.userSearches.length, 1)
})
