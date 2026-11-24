import test from 'node:test'
import assert from 'node:assert/strict'
import { createAuthorizationService } from '../src/modules/authorization/authorization.service.js'

const userId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'

function serviceWithRoles(roles) {
  return createAuthorizationService({
    authorizationRepository: {
      async findRoleCodesByUserId(value) {
        assert.equal(value, userId)
        return roles
      },
    },
  })
}

test('the same account can pass advisor and course-manager role gates when assigned both', async () => {
  const service = serviceWithRoles(['advisor', 'course_manager'])
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['advisor'] }), true)
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['course_manager'] }), true)
})

test('an advisor assignment does not automatically grant course-manager access', async () => {
  const service = serviceWithRoles(['advisor'])
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['course_manager'] }), false)
})

test('a course-manager assignment does not automatically grant advisor access', async () => {
  const service = serviceWithRoles(['course_manager'])
  assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['advisor'] }), false)
})

test('academic role combinations do not grant system-admin access', async () => {
  for (const roles of [['course_manager'], ['advisor', 'course_manager']]) {
    const service = serviceWithRoles(roles)
    assert.equal(await service.hasAnyRole({ userId, allowedRoles: ['system_admin'] }), false)
  }
})
