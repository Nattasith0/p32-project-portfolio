import { parseUserRolesUserId } from './user-roles.validation.js'

const ROLE_CODE_PATTERN = /^[a-z][a-z0-9_]*$/
const ERROR_MESSAGES = new Map([
  ['INVALID_USER_ROLES_INPUT', 'Invalid user roles input'],
  ['USER_NOT_FOUND', 'User not found'],
])

export class UserRolesError extends Error {
  constructor(code) {
    const message = ERROR_MESSAGES.get(code)
    if (!message) throw new TypeError('Unknown user roles error code')
    super(message)
    this.name = 'UserRolesError'
    this.code = code
  }
}

function isDisplayText(value) {
  return typeof value === 'string' && value.trim().length > 0
}

export function createUserRolesService({ userRolesRepository } = {}) {
  if (typeof userRolesRepository?.findUserRolesByUserId !== 'function') {
    throw new TypeError('A user roles repository is required')
  }

  async function getUserRoles(userId) {
    const targetId = parseUserRolesUserId(userId)
    if (targetId === null) throw new UserRolesError('INVALID_USER_ROLES_INPUT')

    const rows = await userRolesRepository.findUserRolesByUserId(targetId)
    if (!Array.isArray(rows)) throw new TypeError('Invalid user roles result')
    if (rows.length === 0) throw new UserRolesError('USER_NOT_FOUND')

    const first = rows[0]
    if (
      first?.user_id !== targetId ||
      !isDisplayText(first.username) ||
      !isDisplayText(first.display_name) ||
      typeof first.is_active !== 'boolean' ||
      typeof first.email_verified !== 'boolean' ||
      (first.is_active && !first.email_verified)
    ) {
      throw new TypeError('Invalid user roles account')
    }

    const user = {
      userId: targetId,
      username: first.username,
      displayName: first.display_name,
      isActive: first.is_active,
      emailVerified: first.email_verified,
    }
    const roles = []
    const seenRoleCodes = new Set()

    for (const row of rows) {
      if (
        row?.user_id !== user.userId ||
        row.username !== user.username ||
        row.display_name !== user.displayName ||
        row.is_active !== user.isActive ||
        row.email_verified !== user.emailVerified
      ) {
        throw new TypeError('Inconsistent user roles account')
      }

      const { role_code: roleCode, role_name: roleName } = row
      // LEFT JOIN ให้หนึ่งแถวที่บทบาทเป็น null เมื่อบัญชียังไม่มีบทบาท
      if (rows.length === 1 && roleCode === null && roleName === null) break

      if (
        typeof roleCode !== 'string' ||
        roleCode !== roleCode.trim() ||
        !ROLE_CODE_PATTERN.test(roleCode) ||
        !isDisplayText(roleName) ||
        seenRoleCodes.has(roleCode)
      ) {
        throw new TypeError('Invalid user roles assignment')
      }
      seenRoleCodes.add(roleCode)
      roles.push({ roleCode, roleName })
    }

    return { user, roles }
  }

  return { getUserRoles }
}
