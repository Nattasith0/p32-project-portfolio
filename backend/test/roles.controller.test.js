import test from 'node:test'
import assert from 'node:assert/strict'
import { createRoleController } from '../src/modules/roles/roles.controller.js'

function createResponse() {
  const result = { headers: {}, status: null, body: null }
  return {
    result,
    set(name, value) { result.headers[name] = value; return this },
    status(value) { result.status = value; return this },
    json(value) { result.body = value; return this },
  }
}

test('returns HTTP 200 with the service catalog and no-store', async () => {
  const roles = [{ roleCode: 'student', roleName: 'นักศึกษาในโครงงาน' }]
  let calls = 0
  const controller = createRoleController({
    roleService: { async listRoles() { calls += 1; return roles } },
  })
  const response = createResponse()
  await controller.getRoles({}, response)
  assert.deepEqual(response.result, {
    headers: { 'Cache-Control': 'no-store' }, status: 200, body: { roles },
  })
  assert.equal(calls, 1)
})

test('waits for the service before writing a successful response', async () => {
  let resolveRoles
  const controller = createRoleController({
    roleService: { listRoles: () => new Promise((resolve) => { resolveRoles = resolve }) },
  })
  const response = createResponse()
  const pending = controller.getRoles({}, response)
  assert.equal(response.result.status, null)
  resolveRoles([])
  await pending
  assert.equal(response.result.status, 200)
  assert.deepEqual(response.result.body, { roles: [] })
})

test('propagates service errors without writing a successful body', async () => {
  const failure = new Error('TEST_ONLY_SERVICE_FAILURE')
  const controller = createRoleController({
    roleService: { async listRoles() { throw failure } },
  })
  const response = createResponse()
  await assert.rejects(controller.getRoles({}, response), (error) => error === failure)
  assert.equal(response.result.status, null)
  assert.equal(response.result.body, null)
})

test('rejects service responses that are not arrays', async () => {
  for (const roles of [undefined, null, {}, true, 'student']) {
    const controller = createRoleController({ roleService: { listRoles: async () => roles } })
    const response = createResponse()
    await assert.rejects(controller.getRoles({}, response), TypeError)
    assert.equal(response.result.status, null)
  }
})

test('requires a role service with listRoles', () => {
  assert.throws(() => createRoleController(), TypeError)
  for (const roleService of [null, {}, { listRoles: true }]) {
    assert.throws(() => createRoleController({ roleService }), TypeError)
  }
})
