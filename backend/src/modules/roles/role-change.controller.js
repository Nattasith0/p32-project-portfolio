import { RoleChangeError } from './role-change.service.js'
import { parseRoleChangeUuid } from './role-change.validation.js'

const PUBLIC_ERRORS = new Map([
  [
    'INVALID_ROLE_CHANGE_INPUT',
    {
      status: 400,
      message: 'ข้อมูลการเปลี่ยนบทบาทไม่ถูกต้อง',
    },
  ],
  [
    'FORBIDDEN',
    {
      status: 403,
      message: 'คุณไม่มีสิทธิ์ดำเนินการนี้',
    },
  ],
  [
    'ROLE_TARGET_NOT_FOUND',
    {
      status: 404,
      message: 'ไม่พบบัญชีที่ต้องการเปลี่ยนบทบาท',
    },
  ],
  [
    'ROLE_NOT_FOUND',
    {
      status: 404,
      message: 'ไม่พบบทบาทที่ระบุ',
    },
  ],
  [
    'ROLE_TARGET_NOT_READY',
    {
      status: 409,
      message: 'บัญชีนี้ยังไม่พร้อมรับบทบาท',
    },
  ],
  [
    'LAST_SYSTEM_ADMIN',
    {
      status: 409,
      message: 'ไม่สามารถถอนบทบาทผู้ดูแลระบบที่พร้อมใช้คนสุดท้ายได้',
    },
  ],
  [
    'ROLE_CHANGE_BUSY',
    {
      status: 409,
      message: 'มีการเปลี่ยนบทบาทอื่นอยู่ กรุณาตรวจสอบสถานะแล้วลองใหม่',
    },
  ],
])

export function createRoleChangeController({ roleChangeService } = {}) {
  if (typeof roleChangeService?.changeUserRole !== 'function') {
    throw new TypeError('A role change service is required')
  }

  // Router ต้องบังคับ Origin/session/system_admin/CSRF ก่อนถึง controller
  async function changeUserRole(request, response) {
    response.set('Cache-Control', 'no-store')

    const actorUserId = parseRoleChangeUuid(request.auth?.userId)
    const requestId = parseRoleChangeUuid(request.requestId)
    if (actorUserId === null || requestId === null) {
      throw new TypeError('A trusted server role change context is required')
    }

    let result
    try {
      result = await roleChangeService.changeUserRole({
        actorUserId,
        requestId,
        input: request.body,
      })
    } catch (error) {
      const failure =
        error instanceof RoleChangeError ? PUBLIC_ERRORS.get(error.code) : undefined
      if (!failure) throw error

      return response.status(failure.status).json({
        code: error.code,
        message: failure.message,
        request_id: requestId,
      })
    }

    if (!result || Array.isArray(result) || typeof result.changed !== 'boolean') {
      throw new TypeError('Invalid role change controller result')
    }
    const auditId = result.changed ? parseRoleChangeUuid(result.auditId) : null
    if (
      (result.changed && auditId === null) ||
      (!result.changed && result.auditId !== null)
    ) {
      throw new TypeError('Invalid role change controller result')
    }

    return response.status(200).json({ changed: result.changed, auditId })
  }

  return { changeUserRole }
}
