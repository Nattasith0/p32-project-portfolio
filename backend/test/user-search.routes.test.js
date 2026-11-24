import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request as httpRequest } from 'node:http'
import express from 'express'
import { createUserSearchRouter } from '../src/modules/users/user-search.routes.js'
import { createUserSearchRepository } from '../src/modules/users/user-search.repository.js'
import { createUserSearchService } from '../src/modules/users/user-search.service.js'
import { createAuthorizationRepository } from '../src/modules/authorization/authorization.repository.js'
import { createAuthorizationService } from '../src/modules/authorization/authorization.service.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { requestContext } from '../src/middleware/request-context.middleware.js'
import { createRequireOrigin } from '../src/middleware/origin.middleware.js'
import { createApiErrorHandler } from '../src/middleware/api-error.middleware.js'

const actorIds = {
  admin: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  student: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  faculty: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
}
const rows = [1, 2, 3].map((number) => ({
  user_id: `00000000-0000-4000-8000-00000000000${number}`,
  username: `student_${number}`,
  display_name: `นักศึกษาทดสอบ ${number}`,
  is_active: true,
  email_verified: true,
  email: 'PRIVATE_TEST_ONLY',
  password_hash: 'PRIVATE_TEST_ONLY',
}))
const dto = (row) => ({
  userId: row.user_id,
  username: row.username,
  displayName: row.display_name,
  isActive: row.is_active,
  emailVerified: row.email_verified,
})

async function fixture(t, options = {}) {
  const stats = { roleLookups: [], searches: [], authCalls: 0, logs: [] }
  let adminAllowed = true
  const database = {
    async query(sql, values) {
      if (sql.includes('FROM p32.user_roles')) {
        stats.roleLookups.push(values[0])
        if (options.roleError) throw options.roleError
        const codes =
          values[0] === actorIds.admin
            ? adminAllowed
              ? ['system_admin']
              : []
            : values[0] === actorIds.student
              ? ['student']
              : ['advisor', 'course_manager']
        return { rows: codes.map((role_code) => ({ role_code })) }
      }
      assert.match(sql, /FROM p32\.users/)
      stats.searches.push(values)
      if (options.searchError) throw options.searchError
      if (options.searchRows) return { rows: options.searchRows }
      if (values[0] === '%missing%') return { rows: [] }
      return {
        rows: rows
          .filter((row) => values[1] === null || row.user_id > values[1])
          .slice(0, values[2]),
      }
    },
  }
  const authorizationService = createAuthorizationService({
    authorizationRepository: createAuthorizationRepository(database),
  })
  const userSearchService = createUserSearchService({
    userSearchRepository: createUserSearchRepository(database),
  })
  const requireSession = createRequireSession({
    sessionCookie: createSessionCookie({
      name: 'p32_session_dev',
      options: { httpOnly: true, secure: false, sameSite: 'lax', path: '/' },
    }),
    sessionAuthService: {
      async authenticateSessionToken(token) {
        stats.authCalls += 1
        if (options.rejectSession) return null
        const actor = Object.keys(actorIds).find(
          (name) => token === `${name}.payload.signature`,
        )
        return actor
          ? {
              userId: actorIds[actor],
              sessionId: '11111111-1111-4111-8111-111111111111',
            }
          : null
      },
    },
  })
  const app = express()
  app.use(requestContext)
  app.use(
    '/api/v1/admin/users',
    createRequireOrigin({ webOrigin: 'http://localhost:5173' }),
    createUserSearchRouter({ requireSession, authorizationService, userSearchService }),
  )
  app.use((request, response) =>
    response
      .set('Cache-Control', 'no-store')
      .status(404)
      .json({ code: 'NOT_FOUND', request_id: request.requestId }),
  )
  app.use(
    createApiErrorHandler({
      logger: {
        error(...args) {
          stats.logs.push(args)
        },
      },
    }),
  )
  const server = app.listen(0, '127.0.0.1')
  t.after(
    () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  )
  await once(server, 'listening')
  function send({
    actor = 'admin',
    cookieHeader,
    query = '?q=student',
    headers = {},
    method = 'GET',
  } = {}) {
    const requestHeaders = { ...headers }
    const cookie =
      cookieHeader === undefined
        ? `p32_session_dev=${actor}.payload.signature`
        : cookieHeader
    if (cookie !== null) requestHeaders.Cookie = cookie
    return new Promise((resolve, reject) => {
      const outgoing = httpRequest(
        `http://127.0.0.1:${server.address().port}/api/v1/admin/users${query}`,
        { method, headers: requestHeaders, agent: false, timeout: 5000 },
        (incoming) => {
          const chunks = []
          incoming.on('error', reject)
          incoming.on('data', (chunk) => chunks.push(chunk))
          incoming.on('end', () => {
            try {
              const text = Buffer.concat(chunks).toString('utf8')
              resolve({
                status: incoming.statusCode,
                headers: incoming.headers,
                body: text ? JSON.parse(text) : null,
              })
            } catch (error) {
              reject(error)
            }
          })
        },
      )
      outgoing.on('error', reject)
      outgoing.on('timeout', () =>
        outgoing.destroy(new Error('TEST_ONLY_REQUEST_TIMEOUT')),
      )
      outgoing.end()
    })
  }
  return {
    send,
    stats,
    revokeAdmin() {
      adminAllowed = false
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

test('admin receives only the public search page with cookies unchanged and no-store', async (t) => {
  const { send, stats } = await fixture(t)
  const result = await send()
  assert.equal(result.status, 200)
  assert.deepEqual(result.body, { users: rows.map(dto), nextCursor: null })
  assert.equal(result.headers['cache-control'], 'no-store')
  assert.ok(result.headers['x-request-id'])
  assert.equal(result.headers['set-cookie'], undefined)
  assert.equal(JSON.stringify(result.body).includes('PRIVATE_TEST_ONLY'), false)
  assert.deepEqual(stats.roleLookups, [actorIds.admin])
  assert.deepEqual(stats.searches, [['%student%', null, 21]])
})

test('HTTP cursor pages exclude lookahead and continue without skipped or duplicated users', async (t) => {
  const { send } = await fixture(t)
  const first = await send({ query: '?q=student&limit=1' })
  assert.deepEqual(first.body, { users: [dto(rows[0])], nextCursor: rows[0].user_id })
  const second = await send({
    query: `?q=student&limit=1&after=${first.body.nextCursor}`,
  })
  assert.deepEqual(second.body, { users: [dto(rows[1])], nextCursor: rows[1].user_id })
  const third = await send({
    query: `?q=student&limit=1&after=${second.body.nextCursor}`,
  })
  assert.deepEqual(third.body, { users: [dto(rows[2])], nextCursor: null })
})

test('a successful search with no matches returns an empty page', async (t) => {
  const { send } = await fixture(t)
  const result = await send({ query: '?q=missing' })
  assert.equal(result.status, 200)
  assert.deepEqual(result.body, { users: [], nextCursor: null })
})

test('student and faculty with advisor/course_manager roles are denied before validating or searching', async (t) => {
  const { send, stats } = await fixture(t)
  for (const actor of ['student', 'faculty'])
    assertFailure(await send({ actor, query: '?q=x' }), 403, 'FORBIDDEN')
  assert.equal(stats.searches.length, 0)
})

test('missing or malformed session cookies cannot reach roles or search', async (t) => {
  const { send, stats } = await fixture(t)
  for (const cookieHeader of [null, 'p32_session_dev=invalid'])
    assertFailure(await send({ cookieHeader }), 401, 'AUTH_REQUIRED')
  assert.equal(stats.authCalls, 0)
  assert.equal(stats.roleLookups.length, 0)
  assert.equal(stats.searches.length, 0)
})

test('a session rejected by authentication cannot reach authorization or search', async (t) => {
  const { send, stats } = await fixture(t, { rejectSession: true })
  assertFailure(await send(), 401, 'AUTH_REQUIRED')
  assert.equal(stats.roleLookups.length, 0)
  assert.equal(stats.searches.length, 0)
})

test('client identity and role claims cannot replace the authenticated account', async (t) => {
  const { send, stats } = await fixture(t)
  const query = `?q=student&userId=${actorIds.admin}&role=system_admin`
  const headers = { 'X-User-Id': actorIds.admin, 'X-Role': 'system_admin' }
  assertFailure(await send({ actor: 'student', query, headers }), 403, 'FORBIDDEN')
  assertFailure(await send({ query, headers }), 400, 'INVALID_USER_SEARCH_INPUT')
  assert.deepEqual(stats.roleLookups, [actorIds.student, actorIds.admin])
  assert.equal(stats.searches.length, 0)
})

test('invalid and repeated query fields are HTTP 400 before the account query', async (t) => {
  const { send, stats } = await fixture(t)
  for (const query of [
    '',
    '?q=x',
    '?q=student&limit=51',
    '?q=student&q=admin',
    '?q[name]=student',
    '?q=student&after=bad',
    '?q=student&offset=0',
  ]) {
    assertFailure(await send({ query }), 400, 'INVALID_USER_SEARCH_INPUT')
  }
  assert.equal(stats.searches.length, 0)
})

test('authorization lookup failure is a safe 500 and cannot reach account search', async (t) => {
  const { send, stats } = await fixture(t, {
    roleError: new Error('PRIVATE_TEST_ONLY'),
  })
  const result = await send()
  assertFailure(result, 500, 'INTERNAL_ERROR')
  assert.equal(stats.searches.length, 0)
  assert.equal(
    JSON.stringify([result.body, stats.logs]).includes('PRIVATE_TEST_ONLY'),
    false,
  )
})

test('search failures, timeouts and malformed rows never become HTTP 200 or leak details', async (t) => {
  for (const options of [
    { searchError: new Error('PRIVATE_TEST_ONLY') },
    { searchError: Object.assign(new Error('PRIVATE_TEST_ONLY'), { code: '57014' }) },
    { searchRows: [{}] },
  ]) {
    const { send, stats } = await fixture(t, options)
    const result = await send()
    assertFailure(result, 500, 'INTERNAL_ERROR')
    assert.equal(stats.searches.length, 1)
    assert.equal(
      JSON.stringify([result.body, stats.logs]).includes('PRIVATE_TEST_ONLY'),
      false,
    )
  }
})

test('HEAD applies the same session, role and query rules without a response body', async (t) => {
  const { send } = await fixture(t)
  for (const [options, status] of [
    [{}, 200],
    [{ actor: 'student' }, 403],
    [{ cookieHeader: null }, 401],
    [{ query: '?q=x' }, 400],
  ]) {
    const result = await send({ ...options, method: 'HEAD' })
    assert.equal(result.status, status)
    assert.equal(result.body, null)
  }
})

test('unsupported POST never searches and unsafe origins are rejected before session lookup', async (t) => {
  const { send, stats } = await fixture(t)
  assertFailure(await send({ method: 'POST' }), 403, 'ORIGIN_NOT_ALLOWED')
  assert.equal(stats.authCalls, 0)
  assert.equal(
    (await send({ method: 'POST', headers: { Origin: 'http://localhost:5173' } }))
      .status,
    404,
  )
  assert.equal(stats.searches.length, 0)
})

test('revoked admin permission is checked again on the next request', async (t) => {
  const { send, stats, revokeAdmin } = await fixture(t)
  assert.equal((await send()).status, 200)
  revokeAdmin()
  assertFailure(await send(), 403, 'FORBIDDEN')
  assert.equal(stats.roleLookups.length, 2)
  assert.equal(stats.searches.length, 1)
})

test('router rejects incomplete dependencies before serving requests', () => {
  assert.throws(() => createUserSearchRouter(), TypeError)
  assert.throws(() => createUserSearchRouter({ requireSession: true }), TypeError)
  assert.throws(() => createUserSearchRouter({ requireSession() {} }), TypeError)
  assert.throws(
    () =>
      createUserSearchRouter({
        requireSession() {},
        authorizationService: { hasAnyRole: async () => true },
      }),
    TypeError,
  )
})
