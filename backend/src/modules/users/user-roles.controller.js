import { UserRolesError } from './user-roles.service.js'

const PUBLIC_ERRORS = new Map([
  [
    'INVALID_USER_ROLES_INPUT',
    { status: 400, message: 'ข้อมูลคำขออ่านบทบาทไม่ถูกต้อง' },
  ],
  ['USER_NOT_FOUND', { status: 404, message: 'ไม่พบบัญชีที่เลือก' }],
])

export function createUserRolesController({ userRolesService } = {}) {
  if (typeof userRolesService?.getUserRoles !== 'function') {
    throw new TypeError('A user roles service is required')
  }

  async function getUserRoles(request, response) {
    response.set('Cache-Control', 'no-store')
    try {
      if (Object.keys(request.query).length > 0) {
        throw new UserRolesError('INVALID_USER_ROLES_INPUT')
      }
      const result = await userRolesService.getUserRoles(request.params.userId)
      return response.status(200).json(result)
    } catch (error) {
      const failure =
        error instanceof UserRolesError ? PUBLIC_ERRORS.get(error.code) : undefined
      if (!failure) throw error
      return response.status(failure.status).json({
        code: error.code,
        message: failure.message,
        request_id: request.requestId,
      })
    }
  }

  return { getUserRoles }
}
