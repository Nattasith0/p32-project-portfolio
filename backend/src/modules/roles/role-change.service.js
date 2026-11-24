import { parseRoleChangeInput, parseRoleChangeUuid } from './role-change.validation.js'

const DATABASE_ERRORS = new Map([
  ['P3202', 'FORBIDDEN'],
  ['P3203', 'ROLE_TARGET_NOT_FOUND'],
  ['P3204', 'ROLE_NOT_FOUND'],
  ['P3205', 'ROLE_TARGET_NOT_READY'],
  ['P3206', 'LAST_SYSTEM_ADMIN'],
  ['P3207', 'ROLE_CHANGE_BUSY'],
])
const KNOWN_ERRORS = new Set(['INVALID_ROLE_CHANGE_INPUT', ...DATABASE_ERRORS.values()])

export class RoleChangeError extends Error {
  constructor(code) {
    super('Role change request rejected')
    if (!KNOWN_ERRORS.has(code)) throw new TypeError('Unknown role change error code')
    this.name = 'RoleChangeError'
    this.code = code
  }
}

export function createRoleChangeService({ roleChangeRepository } = {}) {
  if (typeof roleChangeRepository?.changeUserRole !== 'function') {
    throw new TypeError('A role change repository is required')
  }

  async function changeUserRole({ actorUserId, requestId, input } = {}) {
    const actor = parseRoleChangeUuid(actorUserId)
    const request = parseRoleChangeUuid(requestId)
    if (actor === null || request === null) {
      throw new TypeError('A valid server role change context is required')
    }

    const change = parseRoleChangeInput(input)
    if (change === null) throw new RoleChangeError('INVALID_ROLE_CHANGE_INPUT')

    try {
      const result = await roleChangeRepository.changeUserRole({
        actorUserId: actor,
        requestId: request,
        ...change,
      })

      if (!result || Array.isArray(result) || typeof result.changed !== 'boolean') {
        throw new TypeError('Invalid role change service result')
      }

      const auditId = result.changed ? parseRoleChangeUuid(result.auditId) : null
      if (
        (result.changed && auditId === null) ||
        (!result.changed && result.auditId !== null)
      ) {
        throw new TypeError('Invalid role change service result')
      }

      return { changed: result.changed, auditId }
    } catch (error) {
      const code = error instanceof Error ? DATABASE_ERRORS.get(error.code) : undefined
      if (code) throw new RoleChangeError(code)

      // รวม P3201: อาจหมายถึง isolation ของ server ผิด จึงไม่เหมารวมเป็น input ผิด
      throw error
    }
  }

  return { changeUserRole }
}