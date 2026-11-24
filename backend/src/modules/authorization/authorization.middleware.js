import { ROLE_CODES } from './authorization.service.js'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export function createRequireRoles({ authorizationService, allowedRoles } = {}) {
  if (typeof authorizationService?.hasAnyRole !== 'function') {
    throw new TypeError('An authorization service is required')
  }

  if (
    !Array.isArray(allowedRoles) ||
    allowedRoles.length === 0 ||
    Array.from(allowedRoles).some((role) => !ROLE_CODES.includes(role))
  ) {
    throw new TypeError('Known allowed roles are required')
  }

  // กฎกำหนดตอนประกอบ route ไม่เปลี่ยนตามข้อมูลที่ client ส่งมา
  const rolePolicy = Object.freeze([...new Set(allowedRoles)])

  // วางหลัง requestContext และ requireSession
  return async function requireRoles(request, response, next) {
    response.set('Cache-Control', 'no-store')
    const userId = request.auth?.userId

    if (
      typeof userId !== 'string' ||
      userId.length !== 36 ||
      !UUID_PATTERN.test(userId)
    ) {
      response.set('WWW-Authenticate', 'Session realm="P32"')
      return response.status(401).json({
        code: 'AUTH_REQUIRED',
        message: 'กรุณาเข้าสู่ระบบ',
        request_id: request.requestId,
      })
    }

    const allowed = await authorizationService.hasAnyRole({
      userId,
      allowedRoles: rolePolicy,
    })

    if (allowed !== true && allowed !== false) {
      throw new TypeError('Invalid authorization decision')
    }

    if (!allowed) {
      return response.status(403).json({
        code: 'FORBIDDEN',
        message: 'คุณไม่มีสิทธิ์ดำเนินการนี้',
        request_id: request.requestId,
      })
    }

    return next()
  }
}
