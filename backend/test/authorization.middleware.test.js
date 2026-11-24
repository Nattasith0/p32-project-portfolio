import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request as httpRequest } from 'node:http'
import express from 'express'
import { createRequireRoles } from '../src/modules/authorization/authorization.middleware.js'
import { createAuthorizationService } from '../src/modules/authorization/authorization.service.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

const TEST_TOKEN = 'test.payload.signature'
const TEST_COOKIE = `p32_session_dev=${TEST_TOKEN}`
const identity = Object.freeze({
  userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
})

async function fixture(t, options = {}) {
  const stats = { authenticated: 0, decisions: [], lookups: [], handled: 0, logs: [] }
  const service = createAuthorizationService({
    authorizationRepository: {
      async findRoleCodesByUserId(userId) {
        stats.lookups.push(userId)
        if (options.repositoryError) throw options.repositoryError
        return options.roles ?? ['student']
      },
    },
  })
  const authorizationService = {
    async hasAnyRole(input) {
      stats.decisions.push(input)
      if (Object.hasOwn(options, 'decision')) return options.decision
      return service.hasAnyRole(input)
    },
  }
  const sessionCookie = createSessionCookie({
    name: 'p32_session_dev',
    options: { httpOnly: true, secure: false, sameSite: 'lax', path: '/' },
  })
  const requireSession = createRequireSession({
    sessionCookie,
    sessionAuthService: {
      async authenticateSessionToken(token) {
        stats.authenticated += 1
        return token === TEST_TOKEN ? (options.identity ?? identity) : null
      },
    },
  })
  const requireRoles = createRequireRoles({
    authorizationService,
    allowedRoles: options.allowedRoles ?? ['student'],
  })
  const app = express()
  app.use(requestContext)
  app.use(express.json({ limit: '16kb' }))
  const middleware = options.useAuthentication === false ? [] : [requireSession]
  app.all('/protected', ...middleware, requireRoles, (request, response) => {
    assert.equal(request.auth, options.identity ?? identity)
    stats.handled += 1
    response.status(204).end()
  })
  app.use(createApiErrorHandler({ logger: { error(...args) { stats.logs.push(args) } } }))
  const server = app.listen(0, '127.0.0.1')
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve())
  }))
  await once(server, 'listening')
  const url = `http://127.0.0.1:${server.address().port}/protected`

  function send({ cookie = TEST_COOKIE, query = '', body, headers = {} } = {}) {
    const requestHeaders = { ...headers }
    if (cookie !== null) requestHeaders.Cookie = cookie
    if (body !== undefined) requestHeaders['Content-Type'] = 'application/json'
    return new Promise((resolve, reject) => {
      const request = httpRequest(url + query, {
        method: body === undefined ? 'GET' : 'POST',
        headers: requestHeaders,
        agent: false,
        timeout: 5000,
      }, (response) => {
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
      request.end(body === undefined ? undefined : JSON.stringify(body))
    })
  }
  return { send, stats }
}

function assertFailure(result, status, code) {
  assert.equal(result.status, status)
  assert.equal(result.body.code, code)
  assert.equal(result.body.request_id, result.headers['x-request-id'])
  assert.match(result.body.request_id, /^[0-9a-f-]{36}$/)
  assert.equal(result.headers['cache-control'], 'no-store')
  assert.equal(result.headers['set-cookie'], undefined)
  assert.deepEqual(Object.keys(result.body).sort(), ['code', 'message', 'request_id'])
}

test('allows a matching role after authentication and preserves the auth context', async (t) => {
  const { send, stats } = await fixture(t)
  const result = await send()
  assert.equal(result.status, 204)
  assert.equal(result.headers['cache-control'], 'no-store')
  assert.equal(stats.authenticated, 1)
  assert.deepEqual(stats.lookups, [identity.userId])
  assert.equal(stats.handled, 1)
})

test('rejects a missing required role with a safe HTTP 403', async (t) => {
  const { send, stats } = await fixture(t, { allowedRoles: ['advisor'] })
  const result = await send()
  assertFailure(result, 403, 'FORBIDDEN')
  assert.equal(result.body.message, 'คุณไม่มีสิทธิ์ดำเนินการนี้')
  assert.equal(result.headers['www-authenticate'], undefined)
  assert.equal(stats.handled, 0)
})

test('rejects an account without eligible roles', async (t) => {
  const { send, stats } = await fixture(t, { roles: [] })
  assertFailure(await send(), 403, 'FORBIDDEN')
  assert.equal(stats.handled, 0)
})

test('rejects missing or invalid sessions before role lookup', async (t) => {
  const { send, stats } = await fixture(t)
  for (const cookie of [null, 'p32_session_dev=bad.payload.signature']) {
    const result = await send({ cookie })
    assertFailure(result, 401, 'AUTH_REQUIRED')
    assert.equal(result.headers['www-authenticate'], 'Session realm="P32"')
  }
  assert.equal(stats.decisions.length, 0)
  assert.equal(stats.lookups.length, 0)
  assert.equal(stats.handled, 0)
})

test('requires an auth context even if session middleware was omitted', async (t) => {
  const { send, stats } = await fixture(t, { useAuthentication: false })
  assertFailure(await send(), 401, 'AUTH_REQUIRED')
  assert.equal(stats.decisions.length, 0)
  assert.equal(stats.handled, 0)
})

test('rejects malformed authenticated identifiers before calling the service', async (t) => {
  for (const userId of [undefined, null, 1, '', 'student_demo', identity.userId + '\n']) {
    const { send, stats } = await fixture(t, { identity: { ...identity, userId } })
    assertFailure(await send(), 401, 'AUTH_REQUIRED')
    assert.equal(stats.decisions.length, 0)
    assert.equal(stats.handled, 0)
  }
})

test('fails safely if role lookup throws without exposing private details', async (t) => {
  const { send, stats } = await fixture(t, { repositoryError: new Error('PRIVATE_TEST_DATA') })
  const result = await send()
  assertFailure(result, 500, 'INTERNAL_ERROR')
  assert.equal(JSON.stringify(result.body).includes('PRIVATE_TEST_DATA'), false)
  assert.equal(JSON.stringify(stats.logs).includes('PRIVATE_TEST_DATA'), false)
  assert.equal(stats.handled, 0)
})

test('rejects service decisions that are not booleans', async (t) => {
  for (const decision of [undefined, null, 0, 1, 'true', {}, []]) {
    const { send, stats } = await fixture(t, { decision })
    assertFailure(await send(), 500, 'INTERNAL_ERROR')
    assert.equal(stats.handled, 0)
  }
})

test('uses the authenticated identifier and server policy instead of client claims', async (t) => {
  const { send, stats } = await fixture(t, { allowedRoles: ['advisor'] })
  const result = await send({
    query: '?userId=forged-user&allowedRoles=student',
    headers: { 'X-User-Id': 'forged-user', 'X-Role': 'advisor' },
    body: { userId: 'forged-user', roles: ['advisor'], allowedRoles: ['student'] },
  })
  assertFailure(result, 403, 'FORBIDDEN')
  assert.deepEqual(stats.decisions, [{ userId: identity.userId, allowedRoles: ['advisor'] }])
  assert.deepEqual(stats.lookups, [identity.userId])
  assert.equal(stats.handled, 0)
})

test('does not give system administrators a bypass for an academic role', async (t) => {
  const denied = await fixture(t, { roles: ['system_admin'], allowedRoles: ['advisor'] })
  assertFailure(await denied.send(), 403, 'FORBIDDEN')
  const allowed = await fixture(t, { roles: ['system_admin'], allowedRoles: ['system_admin'] })
  assert.equal((await allowed.send()).status, 204)
})

test('allows any matching role for a multi-role account', async (t) => {
  const { send } = await fixture(t, { roles: ['advisor', 'examiner'], allowedRoles: ['examiner', 'student'] })
  assert.equal((await send()).status, 204)
})

test('isolates and freezes server policy from later configuration changes', async (t) => {
  const allowedRoles = ['student', 'student']
  const { send, stats } = await fixture(t, { allowedRoles })
  allowedRoles.splice(0, allowedRoles.length, 'system_admin')
  assert.equal((await send()).status, 204)
  assert.deepEqual(stats.decisions[0].allowedRoles, ['student'])
  assert.equal(Object.isFrozen(stats.decisions[0].allowedRoles), true)
})

test('rejects invalid dependencies and policies when creating middleware', () => {
  assert.throws(() => createRequireRoles(), TypeError)
  for (const authorizationService of [null, {}, { hasAnyRole: true }]) {
    assert.throws(() => createRequireRoles({ authorizationService, allowedRoles: ['student'] }), TypeError)
  }
  const authorizationService = { hasAnyRole: async () => true }
  for (const allowedRoles of [undefined, null, 'student', [], ['unknown_role'], ['student', null], new Array(1)]) {
    assert.throws(() => createRequireRoles({ authorizationService, allowedRoles }), TypeError)
  }
})

test('rechecks roles for each request instead of caching an earlier allow decision', async (t) => {
  const options = { roles: ['student'] }
  const { send, stats } = await fixture(t, options)
  assert.equal((await send()).status, 204)
  options.roles = []
  assertFailure(await send(), 403, 'FORBIDDEN')
  assert.equal(stats.lookups.length, 2)
  assert.equal(stats.handled, 1)
})
