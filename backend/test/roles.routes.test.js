import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request as httpRequest } from 'node:http'
import express from 'express'
import { createRoleRouter } from '../src/modules/roles/roles.routes.js'
import { createRoleRepository } from '../src/modules/roles/roles.repository.js'
import { createRoleService } from '../src/modules/roles/roles.service.js'
import { createAuthorizationRepository } from '../src/modules/authorization/authorization.repository.js'
import { createAuthorizationService } from '../src/modules/authorization/authorization.service.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createRequireOrigin } from '../src/middleware/origin.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

const actors = {
  admin: { userId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', sessionId: '11111111-1111-4111-8111-111111111111' },
  student: { userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', sessionId: '22222222-2222-4222-8222-222222222222' },
  faculty: { userId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', sessionId: '33333333-3333-4333-8333-333333333333' },
}
const catalog = [
  { role_code: 'advisor', role_name: 'อาจารย์ที่ปรึกษา' },
  { role_code: 'course_manager', role_name: 'ผู้ดูแลวิชา' },
  { role_code: 'examiner', role_name: 'กรรมการสอบ' },
  { role_code: 'portfolio_viewer', role_name: 'นักศึกษาผู้ชม Portfolio ภายใน' },
  { role_code: 'student', role_name: 'นักศึกษาในโครงงาน' },
  { role_code: 'system_admin', role_name: 'ผู้ดูแลระบบ' },
]
const cookie = (actor) => `p32_session_dev=${actor}.payload.signature`
const expectedRoles = catalog.map((row) => ({ roleCode: row.role_code, roleName: row.role_name }))

async function fixture(t, options = {}) {
  const stats = { roleLookups: [], catalogReads: 0, authCalls: 0, logs: [] }
  const database = {
    async query(sql, values) {
      if (sql.includes('FROM p32.user_roles')) {
        stats.roleLookups.push(values[0])
        if (options.roleError) throw options.roleError
        const roles = values[0] === actors.admin.userId ? ['system_admin']
          : values[0] === actors.student.userId ? ['student'] : ['advisor', 'course_manager']
        return { rows: roles.map((role_code) => ({ role_code })) }
      }
      assert.match(sql, /FROM p32\.roles/)
      stats.catalogReads += 1
      if (options.catalogError) throw options.catalogError
      return { rows: options.catalogRows ?? catalog.map((row) => ({ ...row, private_field: 'PRIVATE_TEST_DATA' })) }
    },
  }
  const authorizationService = createAuthorizationService({
    authorizationRepository: createAuthorizationRepository(database),
  })
  const roleService = options.roleService ?? createRoleService({ roleRepository: createRoleRepository(database) })
  const requireSession = createRequireSession({
    sessionCookie: createSessionCookie({
      name: 'p32_session_dev', options: { httpOnly: true, secure: false, sameSite: 'lax', path: '/' },
    }),
    sessionAuthService: {
      async authenticateSessionToken(token) {
        stats.authCalls += 1
        if (options.rejectSession) return null
        return Object.entries(actors).find(([name]) => token === `${name}.payload.signature`)?.[1] ?? null
      },
    },
  })
  const app = express()
  app.use(requestContext)
  app.use('/api/v1/admin/roles',
    createRequireOrigin({ webOrigin: 'http://localhost:5173' }),
    createRoleRouter({ requireSession, authorizationService, roleService }))
  app.use((request, response) => {
    response.set('Cache-Control', 'no-store')
    response.status(404).json({ code: 'NOT_FOUND', request_id: request.requestId })
  })
  app.use(createApiErrorHandler({ logger: { error(...args) { stats.logs.push(args) } } }))
  const server = app.listen(0, '127.0.0.1')
  t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())))
  await once(server, 'listening')
  const url = `http://127.0.0.1:${server.address().port}/api/v1/admin/roles`

  function send({ actor = 'admin', cookieHeader, query = '', headers = {}, method = 'GET' } = {}) {
    const requestHeaders = { ...headers }
    const cookieValue = cookieHeader === undefined ? cookie(actor) : cookieHeader
    if (cookieValue !== null) requestHeaders.Cookie = cookieValue
    return new Promise((resolve, reject) => {
      const request = httpRequest(url + query, { method, headers: requestHeaders, agent: false, timeout: 5000 }, (response) => {
        const chunks = []
        response.on('error', reject)
        response.on('data', (chunk) => chunks.push(chunk))
        response.on('end', () => {
          try {
            const text = Buffer.concat(chunks).toString('utf8')
            resolve({ status: response.statusCode, headers: response.headers, body: text ? JSON.parse(text) : null })
          } catch (error) { reject(error) }
        })
      })
      request.on('error', reject)
      request.on('timeout', () => request.destroy(new Error('Test request timed out')))
      request.end()
    })
  }
  return { send, stats }
}

function assertFailure(result, status, code) {
  assert.equal(result.status, status)
  assert.equal(result.body.code, code)
  assert.equal(result.body.request_id, result.headers['x-request-id'])
  assert.equal(result.headers['cache-control'], 'no-store')
  assert.equal(result.headers['set-cookie'], undefined)
  assert.deepEqual(Object.keys(result.body).sort(), ['code', 'message', 'request_id'])
}

test('admin receives ordered role metadata with only public fields', async (t) => {
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

test('student and multi-role faculty are denied before catalog lookup', async (t) => {
  const { send, stats } = await fixture(t)
  for (const actor of ['student', 'faculty']) assertFailure(await send({ actor }), 403, 'FORBIDDEN')
  assert.equal(stats.catalogReads, 0)
})

test('missing or malformed session cookies are denied before any role query', async (t) => {
  const { send, stats } = await fixture(t)
  for (const cookieHeader of [null, 'p32_session_dev=malformed']) {
    assertFailure(await send({ cookieHeader }), 401, 'AUTH_REQUIRED')
  }
  assert.equal(stats.authCalls, 0)
  assert.equal(stats.roleLookups.length, 0)
  assert.equal(stats.catalogReads, 0)
})

test('sessions rejected by authentication cannot reach role or catalog lookup', async (t) => {
  const { send, stats } = await fixture(t, { rejectSession: true })
  assertFailure(await send(), 401, 'AUTH_REQUIRED')
  assert.equal(stats.roleLookups.length, 0)
  assert.equal(stats.catalogReads, 0)
})

test('client identifiers and role claims do not replace the authenticated student', async (t) => {
  const { send, stats } = await fixture(t)
  const result = await send({
    actor: 'student', query: `?userId=${actors.admin.userId}&allowedRoles=student&role=system_admin`,
    headers: { 'X-User-Id': actors.admin.userId, 'X-Role': 'system_admin' },
  })
  assertFailure(result, 403, 'FORBIDDEN')
  assert.deepEqual(stats.roleLookups, [actors.student.userId])
  assert.equal(stats.catalogReads, 0)
})

test('role lookup errors fail before catalog lookup without leaking details', async (t) => {
  const { send, stats } = await fixture(t, { roleError: new Error('PRIVATE_TEST_DATA') })
  const result = await send()
  assertFailure(result, 500, 'INTERNAL_ERROR')
  assert.equal(stats.catalogReads, 0)
  assert.equal(JSON.stringify([result.body, stats.logs]).includes('PRIVATE_TEST_DATA'), false)
})

test('catalog lookup errors and invalid rows never become successful responses', async (t) => {
  for (const options of [{ catalogError: new Error('PRIVATE_TEST_DATA') }, { catalogRows: [{}] }]) {
    const { send, stats } = await fixture(t, options)
    const result = await send()
    assertFailure(result, 500, 'INTERNAL_ERROR')
    assert.equal(JSON.stringify([result.body, stats.logs]).includes('PRIVATE_TEST_DATA'), false)
  }
})

test('HEAD uses the same authentication and role policy', async (t) => {
  const { send } = await fixture(t)
  assert.equal((await send({ method: 'HEAD' })).status, 200)
  assert.equal((await send({ method: 'HEAD', actor: 'student' })).status, 403)
  const unauthenticated = await send({ method: 'HEAD', cookieHeader: null })
  assert.equal(unauthenticated.status, 401)
  assert.equal(unauthenticated.body, null)
})

test('unsupported POST does not invoke catalog lookup', async (t) => {
  const { send, stats } = await fixture(t)
  assert.equal((await send({ method: 'POST', headers: { Origin: 'http://localhost:5173' } })).status, 404)
  assert.equal(stats.catalogReads, 0)
})

test('router rejects missing dependencies before it can serve requests', () => {
  assert.throws(() => createRoleRouter(), TypeError)
  assert.throws(() => createRoleRouter({ requireSession: true }), TypeError)
  assert.throws(() => createRoleRouter({ requireSession() {} }), TypeError)
  assert.throws(() => createRoleRouter({ requireSession() {}, authorizationService: { hasAnyRole: async () => true } }), TypeError)
})
