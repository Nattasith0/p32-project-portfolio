import type { RoleDefinition } from '../types/roles'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const ROLE_CODE_PATTERN = /^[a-z][a-z0-9_]*$/

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export class RoleCatalogApiError extends Error {
  readonly status: number
  readonly requestId: string | null

  constructor(response: Response) {
    super('Role catalog request failed')
    this.name = 'RoleCatalogApiError'
    this.status = response.status

    const requestId = response.headers.get('x-request-id')
    this.requestId =
      requestId?.length === 36 && UUID_PATTERN.test(requestId) ? requestId : null
  }
}

export function readRoleDefinitions(data: unknown): RoleDefinition[] {
  if (!isRecord(data) || !Array.isArray(data.roles)) {
    throw new TypeError('Invalid role catalog response')
  }

  const seenCodes = new Set<string>()
  return Array.from(data.roles, (role: unknown) => {
    if (
      !isRecord(role) ||
      typeof role.roleCode !== 'string' ||
      role.roleCode !== role.roleCode.trim() ||
      !ROLE_CODE_PATTERN.test(role.roleCode) ||
      typeof role.roleName !== 'string' ||
      role.roleName.trim().length === 0 ||
      seenCodes.has(role.roleCode)
    ) {
      throw new TypeError('Invalid role catalog response')
    }

    seenCodes.add(role.roleCode)
    return { roleCode: role.roleCode, roleName: role.roleName }
  })
}

export async function getRoleCatalog(signal?: AbortSignal): Promise<RoleDefinition[]> {
  const response = await fetch('/api/v1/admin/roles', {
    method: 'GET',
    signal,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    headers: { Accept: 'application/json' },
  })

  // คง 401/403 แยกจากระบบขัดข้อง ไม่แปลงทุก error เป็นรายการว่าง
  // ไม่อ่าน/นำข้อความ error ภายในของ server ไปแสดงต่อผู้ใช้
  if (response.status !== 200) throw new RoleCatalogApiError(response)

  return readRoleDefinitions(await response.json())
}
