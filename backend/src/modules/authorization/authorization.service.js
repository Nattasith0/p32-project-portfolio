const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export const ROLE_CODES = Object.freeze([
  'student',
  'advisor',
  'course_manager',
  'examiner',
  'portfolio_viewer',
  'system_admin',
])

export function createAuthorizationService({ authorizationRepository } = {}) {
  if (typeof authorizationRepository?.findRoleCodesByUserId !== 'function') {
    throw new TypeError('An authorization repository is required')
  }

  // userId มาจากตัวตนที่ตรวจแล้ว; allowedRoles เป็นกฎที่ Backend กำหนด
  async function hasAnyRole({ userId, allowedRoles } = {}) {
    if (
      typeof userId !== 'string' ||
      userId.length !== 36 ||
      !UUID_PATTERN.test(userId)
    ) {
      throw new TypeError('A valid user identifier is required')
    }

    if (
      !Array.isArray(allowedRoles) ||
      allowedRoles.length === 0 ||
      Array.from(allowedRoles).some((role) => !ROLE_CODES.includes(role))
    ) {
      throw new TypeError('Known allowed roles are required')
    }

    // เก็บกฎของการตรวจครั้งนี้ก่อนรอฐานข้อมูล
    const allowed = new Set(allowedRoles)
    const roles = await authorizationRepository.findRoleCodesByUserId(
      userId.toLowerCase(),
    )

    if (
      !Array.isArray(roles) ||
      Array.from(roles).some((role) => !ROLE_CODES.includes(role))
    ) {
      throw new TypeError('Invalid role lookup result')
    }

    return roles.some((role) => allowed.has(role))
  }

  return { hasAnyRole }
}
