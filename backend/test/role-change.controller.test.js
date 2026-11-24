import test from 'node:test'
import assert from 'node:assert/strict'
import { createRoleChangeController } from '../src/modules/roles/role-change.controller.js'
import {
  createRoleChangeService,
  RoleChangeError,
} from '../src/modules/roles/role-change.service.js'

const ACTOR = '00000000-0000-4000-8000-000000000001'
const TARGET = '00000000-0000-4000-8000-000000000002'
const REQUEST = '00000000-0000-4000-8000-000000000301'
const AUDIT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

function createRequest() {
  return {
    auth: { userId: ACTOR },
    requestId: REQUEST,
    body: {
      targetUserId: TARGET,
      roleCode: 'advisor',
      action: 'assign',
      reason: 'มอบหมายตามหน้าที่',
    },
    query: { actorUserId: TARGET, requestId: TARGET },
    headers: { 'x-user-id': TARGET, 'x-request-id': TARGET },
  }
}

function createResponse() {
  const result = { headers: {}, status: null, body: null }
  return {
    result,
    set(name, value) {
      result.headers[name] = value
      return this
    },
    status(value) {
      result.status = value
      return this
    },
    json(value) {
      result.body = value
      return this
    },
  }
}

test('uses authenticated server context and returns only changed and auditId', async () => {
  const request = createRequest()
  const calls = []
  const controller = createRoleChangeController({
    roleChangeService: {
      async changeUserRole(context) {
        calls.push(context)
        return { changed: true, auditId: AUDIT, privateDetail: 'MUST_NOT_LEAK' }
      },
    },
  })
  const response = createResponse()
  await controller.changeUserRole(request, response)
  assert.deepEqual(calls, [
    { actorUserId: ACTOR, requestId: REQUEST, input: request.body },
  ])
  assert.equal(calls[0].input, request.body)
  assert.deepEqual(response.result, {
    headers: { 'Cache-Control': 'no-store' },
    status: 200,
    body: { changed: true, auditId: AUDIT },
  })
})

test('returns HTTP 200 with false and null for a no-op', async () => {
  const controller = createRoleChangeController({
    roleChangeService: {
      changeUserRole: async () => ({ changed: false, auditId: null }),
    },
  })
  const response = createResponse()
  await controller.changeUserRole(createRequest(), response)
  assert.equal(response.result.status, 200)
  assert.deepEqual(response.result.body, { changed: false, auditId: null })
})

test('waits for the service before sending success and calls it once', async () => {
  let finish
  let calls = 0
  const controller = createRoleChangeController({
    roleChangeService: {
      changeUserRole() {
        calls += 1
        return new Promise((resolve) => {
          finish = resolve
        })
      },
    },
  })
  const response = createResponse()
  const pending = controller.changeUserRole(createRequest(), response)
  assert.equal(response.result.status, null)
  assert.equal(response.result.body, null)
  finish({ changed: true, auditId: AUDIT })
  await pending
  assert.equal(response.result.status, 200)
  assert.equal(calls, 1)
})

const cases = [
  ['INVALID_ROLE_CHANGE_INPUT', 400, 'ข้อมูลการเปลี่ยนบทบาทไม่ถูกต้อง'],
  ['FORBIDDEN', 403, 'คุณไม่มีสิทธิ์ดำเนินการนี้'],
  ['ROLE_TARGET_NOT_FOUND', 404, 'ไม่พบบัญชีที่ต้องการเปลี่ยนบทบาท'],
  ['ROLE_NOT_FOUND', 404, 'ไม่พบบทบาทที่ระบุ'],
  ['ROLE_TARGET_NOT_READY', 409, 'บัญชีนี้ยังไม่พร้อมรับบทบาท'],
  ['LAST_SYSTEM_ADMIN', 409, 'ไม่สามารถถอนบทบาทผู้ดูแลระบบที่พร้อมใช้คนสุดท้ายได้'],
  ['ROLE_CHANGE_BUSY', 409, 'มีการเปลี่ยนบทบาทอื่นอยู่ กรุณาตรวจสอบสถานะแล้วลองใหม่'],
]

for (const [code, status, message] of cases) {
  test(`maps ${code} to HTTP ${status} with a fixed safe response`, async () => {
    const failure = new RoleChangeError(code)
    failure.message = 'PRIVATE_DATABASE_DETAIL'
    failure.detail = 'PRIVATE_DATABASE_DETAIL'
    failure.status = 200
    let calls = 0
    const controller = createRoleChangeController({
      roleChangeService: {
        async changeUserRole() {
          calls += 1
          throw failure
        },
      },
    })
    const response = createResponse()
    await controller.changeUserRole(createRequest(), response)
    assert.deepEqual(response.result, {
      headers: { 'Cache-Control': 'no-store' },
      status,
      body: { code, message, request_id: REQUEST },
    })
    assert.equal(calls, 1)
    assert.doesNotMatch(JSON.stringify(response.result), /PRIVATE_DATABASE_DETAIL/)
  })
}

test('forwards unexpected SQL and network failures without retry or success', async () => {
  for (const code of ['P3201', '23503', 'ECONNRESET', '57014', 'FORBIDDEN']) {
    const failure = Object.assign(new Error('PRIVATE_FAILURE'), { code, status: 400 })
    let calls = 0
    const controller = createRoleChangeController({
      roleChangeService: {
        async changeUserRole() {
          calls += 1
          throw failure
        },
      },
    })
    const response = createResponse()
    await assert.rejects(
      controller.changeUserRole(createRequest(), response),
      (error) => error === failure,
    )
    assert.equal(calls, 1)
    assert.equal(response.result.status, null)
    assert.equal(response.result.body, null)
    assert.equal(response.result.headers['Cache-Control'], 'no-store')
  }
})

test('does not trust lookalike domain errors or unknown domain codes', async () => {
  const unknown = new RoleChangeError('FORBIDDEN')
  unknown.code = 'UNKNOWN'
  for (const failure of [{ name: 'RoleChangeError', code: 'FORBIDDEN' }, unknown]) {
    const controller = createRoleChangeController({
      roleChangeService: {
        async changeUserRole() {
          throw failure
        },
      },
    })
    const response = createResponse()
    await assert.rejects(
      controller.changeUserRole(createRequest(), response),
      (error) => error === failure,
    )
    assert.equal(response.result.status, null)
  }
})

test('rejects missing server identity or request ID before calling the service', async () => {
  let calls = 0
  const controller = createRoleChangeController({
    roleChangeService: {
      async changeUserRole() {
        calls += 1
        assert.fail('must not call')
      },
    },
  })
  const requests = [
    { ...createRequest(), auth: undefined },
    { ...createRequest(), auth: { userId: 'invalid' } },
    { ...createRequest(), requestId: undefined },
    { ...createRequest(), requestId: 'invalid' },
  ]
  for (const request of requests) {
    const response = createResponse()
    await assert.rejects(controller.changeUserRole(request, response), TypeError)
    assert.equal(response.result.status, null)
  }
  assert.equal(calls, 0)
})

test('real validation rejects forged body context before the repository is called', async () => {
  let calls = 0
  const controller = createRoleChangeController({
    roleChangeService: createRoleChangeService({
      roleChangeRepository: {
        async changeUserRole() {
          calls += 1
          assert.fail('must not call')
        },
      },
    }),
  })
  const request = createRequest()
  request.body.actorUserId = TARGET
  request.body.requestId = TARGET
  const response = createResponse()
  await controller.changeUserRole(request, response)
  assert.deepEqual(response.result.body, {
    code: 'INVALID_ROLE_CHANGE_INPUT',
    message: 'ข้อมูลการเปลี่ยนบทบาทไม่ถูกต้อง',
    request_id: REQUEST,
  })
  assert.equal(response.result.status, 400)
  assert.equal(calls, 0)
})

test('passes normalized input through the real service and projects repository output', async () => {
  const calls = []
  const controller = createRoleChangeController({
    roleChangeService: createRoleChangeService({
      roleChangeRepository: {
        async changeUserRole(context) {
          calls.push(context)
          return { changed: true, auditId: AUDIT.toUpperCase(), hidden: 'PRIVATE' }
        },
      },
    }),
  })
  const request = createRequest()
  request.body.reason = '  มอบหมายตามหน้าที่  '
  const response = createResponse()
  await controller.changeUserRole(request, response)
  assert.deepEqual(calls, [
    {
      actorUserId: ACTOR,
      requestId: REQUEST,
      targetUserId: TARGET,
      roleCode: 'advisor',
      action: 'assign',
      reason: 'มอบหมายตามหน้าที่',
    },
  ])
  assert.deepEqual(response.result.body, { changed: true, auditId: AUDIT })
  assert.equal(request.body.reason, '  มอบหมายตามหน้าที่  ')
})

test('rejects malformed service results before writing a success response', async () => {
  const invalid = [
    null,
    undefined,
    [],
    {},
    { changed: 1, auditId: AUDIT },
    { changed: true, auditId: null },
    { changed: true, auditId: 'invalid' },
    { changed: false, auditId: AUDIT },
    { changed: false },
  ]
  for (const result of invalid) {
    const controller = createRoleChangeController({
      roleChangeService: { changeUserRole: async () => result },
    })
    const response = createResponse()
    await assert.rejects(controller.changeUserRole(createRequest(), response), TypeError)
    assert.equal(response.result.status, null)
    assert.equal(response.result.body, null)
  }
})

test('requires a service with a changeUserRole method', () => {
  assert.throws(() => createRoleChangeController(), TypeError)
  for (const roleChangeService of [null, {}, { changeUserRole: true }]) {
    assert.throws(() => createRoleChangeController({ roleChangeService }), TypeError)
  }
})
