import type { AdminUser, AdminUserRoles, AdminUserSearchPage } from '../types/adminUsers'
import { readRoleDefinitions } from './rolesApi'

const USERS_PATH = '/api/v1/admin/users'
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && value.length === 36 && UUID_PATTERN.test(value)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export class AdminUsersApiError extends Error {
  readonly status: number
  readonly requestId: string | null

  constructor(response: Response) {
    super('Admin users request failed')
    this.name = 'AdminUsersApiError'
    this.status = response.status
    const requestId = response.headers.get('x-request-id')
    this.requestId = isUuid(requestId) ? requestId : null
  }
}

async function getAdminJson(path: string, signal?: AbortSignal): Promise<unknown> {
  const response = await fetch(path, {
    method: 'GET',
    signal,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    headers: { Accept: 'application/json' },
  })
  if (response.status !== 200) throw new AdminUsersApiError(response)
  return response.json()
}

function readAdminUser(value: unknown): AdminUser {
  if (!isRecord(value)) throw new TypeError('Invalid admin user response')
  const { userId, username, displayName, isActive, emailVerified } = value
  if (
    !isUuid(userId) ||
    userId !== userId.toLowerCase() ||
    typeof username !== 'string' ||
    username.trim().length === 0 ||
    typeof displayName !== 'string' ||
    displayName.trim().length === 0 ||
    typeof isActive !== 'boolean' ||
    typeof emailVerified !== 'boolean' ||
    (isActive && !emailVerified)
  ) {
    throw new TypeError('Invalid admin user response')
  }
  return { userId, username, displayName, isActive, emailVerified }
}

type SearchAdminUsersInput = { q: string; limit?: number; after?: string | null }

export async function searchAdminUsers(
  { q, limit = 20, after = null }: SearchAdminUsersInput,
  signal?: AbortSignal,
): Promise<AdminUserSearchPage> {
  if (typeof q !== 'string' || q.includes('\0') || /[\uD800-\uDFFF]/u.test(q)) {
    throw new TypeError('Invalid account search text')
  }
  if (!Number.isInteger(limit) || limit < 1 || limit > 50 || (after !== null && !isUuid(after))) {
    throw new TypeError('Invalid account search pagination')
  }

  const params = new URLSearchParams({ q, limit: String(limit) })
  const cursor = after?.toLowerCase() ?? null
  if (cursor !== null) params.set('after', cursor)
  const data = await getAdminJson(`${USERS_PATH}?${params}`, signal)
  if (!isRecord(data) || !Array.isArray(data.users) || data.users.length > limit) {
    throw new TypeError('Invalid account search page')
  }

  let previousId = cursor
  const users = Array.from(data.users, (entry: unknown) => {
    const user = readAdminUser(entry)
    if (previousId !== null && user.userId <= previousId) {
      throw new TypeError('Invalid account search order')
    }
    previousId = user.userId
    return user
  })
  const nextCursor = data.nextCursor
  if (
    nextCursor !== null &&
    (!isUuid(nextCursor) || users.length !== limit || nextCursor !== users.at(-1)?.userId)
  ) {
    throw new TypeError('Invalid next account search cursor')
  }
  return { users, nextCursor }
}

export async function getAdminUserRoles(
  userId: string,
  signal?: AbortSignal,
): Promise<AdminUserRoles> {
  if (!isUuid(userId)) throw new TypeError('Invalid target user ID')
  const targetId = userId.toLowerCase()
  const data = await getAdminJson(`${USERS_PATH}/${targetId}/roles`, signal)
  if (!isRecord(data)) throw new TypeError('Invalid user roles response')
  const user = readAdminUser(data.user)
  if (user.userId !== targetId) throw new TypeError('Unexpected user roles account')
  return { user, roles: readRoleDefinitions(data) }
}
