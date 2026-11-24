import test from 'node:test'
import assert from 'node:assert/strict'
import { createAuthorizationService } from '../src/modules/authorization/authorization.service.js'

const userId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'

function serviceWithRoles(roles) {
  return createAuthorizationService({
    authorizationRepository: {
      findRoleCodesByUserId: async () => roles,
    },
  })
}

test('allows a matching role', async () => {
  const service = serviceWithRoles(['student'])
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['student'] }), true)
})

test('allows any matching role for an account with multiple roles', async () => {
  const service = serviceWithRoles(['advisor', 'examiner'])
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['student', 'examiner'] }), true)
})

test('denies an account without a matching role', async () => {
  const service = serviceWithRoles(['student'])
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['advisor'] }), false)
})

test('denies an account with no eligible roles', async () => {
  const service = serviceWithRoles([])
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['student'] }), false)
})

test('does not give system administrators an automatic academic role bypass', async () => {
  const service = serviceWithRoles(['system_admin'])
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['advisor'] }), false)
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['system_admin'] }), true)
})

test('normalizes UUIDs before lookup without changing input', async () => {
  const input = Object.freeze({
    userId: userId.toUpperCase(),
    allowedRoles: Object.freeze(['student']),
  })
  const service = createAuthorizationService({
    authorizationRepository: {
      async findRoleCodesByUserId(value) {
        assert.equal(value, userId)
        return Object.freeze(['student'])
      },
    },
  })
  assert.equal(await service.hasAnyRole(input), true)
  assert.equal(input.userId, userId.toUpperCase())
})

test('rejects invalid user identifiers before repository lookup', async () => {
  let calls = 0
  const service = createAuthorizationService({
    authorizationRepository: {
      async findRoleCodesByUserId() { calls += 1; return ['student'] },
    },
  })
  for (const value of [undefined, null, 1, '', 'student_demo', userId + '\n', ' ' + userId]) {
    await assert.rejects(service.hasAnyRole({ userId: value, allowedRoles: ['student'] }), TypeError)
  }
  assert.equal(calls, 0)
})

test('rejects invalid allowed-role policies before repository lookup', async () => {
  let calls = 0
  const service = createAuthorizationService({
    authorizationRepository: {
      async findRoleCodesByUserId() { calls += 1; return ['student'] },
    },
  })
  for (const allowedRoles of [undefined, null, 'student', [], ['unknown_role'], ['student', null], ['Student'], new Array(1)]) {
    await assert.rejects(service.hasAnyRole({ userId, allowedRoles }), TypeError)
  }
  assert.equal(calls, 0)
})

test('rejects malformed repository results instead of granting access', async () => {
  for (const roles of [undefined, null, true, 'student', {}, [null], ['student', 'unknown_role'], new Array(1)]) {
    const service = serviceWithRoles(roles)
    await assert.rejects(service.hasAnyRole({ userId, allowedRoles: ['student'] }), TypeError)
  }
})

test('propagates lookup failures instead of returning an authorization decision', async () => {
  const failure = new Error('TEST_ONLY_DATABASE_FAILURE')
  const service = createAuthorizationService({
    authorizationRepository: {
      async findRoleCodesByUserId() { throw failure },
    },
  })
  await assert.rejects(
    service.hasAnyRole({ userId, allowedRoles: ['student'] }),
    (error) => error === failure,
  )
})

test('looks up roles on each check so a previous result is not cached', async () => {
  let calls = 0
  const service = createAuthorizationService({
    authorizationRepository: {
      async findRoleCodesByUserId() {
        calls += 1
        return calls === 1 ? ['student'] : []
      },
    },
  })
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['student'] }), true)
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['student'] }), false)
  assert.equal(calls, 2)
})

test('keeps the allowed-role policy stable while awaiting lookup', async () => {
  let resolveRoles
  const service = createAuthorizationService({
    authorizationRepository: {
      findRoleCodesByUserId: () => new Promise((resolve) => { resolveRoles = resolve }),
    },
  })
  const allowedRoles = ['student']
  const result = service.hasAnyRole({ userId, allowedRoles })
  allowedRoles.push('advisor')
  resolveRoles(['advisor'])
  assert.equal(await result, false)
})

test('requires a repository with a role lookup function', () => {
  assert.throws(() => createAuthorizationService(), TypeError)
  for (const authorizationRepository of [null, {}, { findRoleCodesByUserId: true }]) {
    assert.throws(() => createAuthorizationService({ authorizationRepository }), TypeError)
  }
})
