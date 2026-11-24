import type { RoleDefinition } from './roles'

export type AdminUser = {
  userId: string
  username: string
  displayName: string
  isActive: boolean
  emailVerified: boolean
}

export type AdminUserSearchPage = {
  users: AdminUser[]
  nextCursor: string | null
}

export type AdminUserRoles = {
  user: AdminUser
  roles: RoleDefinition[]
}
