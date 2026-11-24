import { AuthApiError, getSessionCsrfToken } from './authApi'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const ERROR_CODES = new Set([
  'AUTH_REQUIRED', 'FORBIDDEN', 'CSRF_INVALID', 'ORIGIN_NOT_ALLOWED',
  'ROLE_TARGET_NOT_FOUND', 'ROLE_NOT_FOUND', 'ROLE_TARGET_NOT_READY',
  'LAST_SYSTEM_ADMIN', 'ROLE_CHANGE_BUSY', 'INVALID_ROLE_CHANGE_INPUT',
])

export type RoleChangeAction = 'assign' | 'revoke'

type RoleChangeInput = {
  targetUserId: string
  roleCode: string
  action: RoleChangeAction
  reason: string
}

type RoleChangeResult = { changed: true; auditId: string } | { changed: false; auditId: null }

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && value.length === 36 && UUID_PATTERN.test(value)
}

export function isRoleChangeReason(reason: string) {
  const length = Array.from(reason.trim()).length
  return length >= 1 && length <= 500 && !reason.includes('\0') && !/[\uD800-\uDFFF]/u.test(reason)
}

export class RoleChangeApiError extends Error {
  constructor(readonly status: number, readonly code: string, readonly requestId: string | null) {
    super('Role change request failed')
    this.name = 'RoleChangeApiError'
  }
}

async function readRoleChangeError(response: Response) {
  const data: unknown = await response.json().catch(() => null)
  const code = isRecord(data) && typeof data.code === 'string' && ERROR_CODES.has(data.code)
    ? data.code
    : 'ROLE_CHANGE_FAILED'
  const requestId = response.headers.get('x-request-id')
  return new RoleChangeApiError(response.status, code, isUuid(requestId) ? requestId : null)
}

export async function changeUserRole(
  { targetUserId, roleCode, action, reason }: RoleChangeInput,
  signal?: AbortSignal,
): Promise<RoleChangeResult> {
  if (!isUuid(targetUserId) || !/^[a-z][a-z_]{0,63}$/.test(roleCode) ||
      (action !== 'assign' && action !== 'revoke') || !isRoleChangeReason(reason)) {
    throw new TypeError('Invalid role change input')
  }

  let csrfToken: string | null
  try {
    csrfToken = await getSessionCsrfToken(signal)
  } catch (error) {
    if (error instanceof AuthApiError) {
      throw new RoleChangeApiError(error.status, error.code, error.requestId)
    }
    throw error
  }

  if (csrfToken === null) throw new RoleChangeApiError(401, 'AUTH_REQUIRED', null)
  signal?.throwIfAborted()

  const response = await fetch('/api/v1/admin/role-changes', {
    method: 'POST',
    signal,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({ targetUserId: targetUserId.toLowerCase(), roleCode, action, reason: reason.trim() }),
  })
  if (response.status !== 200) throw await readRoleChangeError(response)

  const data: unknown = await response.json()
  if (isRecord(data)) {
    if (data.changed === false && data.auditId === null) return { changed: false, auditId: null }
    if (data.changed === true && isUuid(data.auditId)) return { changed: true, auditId: data.auditId }
  }
  throw new TypeError('Invalid role change response')
}
