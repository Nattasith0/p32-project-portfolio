import { Router } from 'express'
import { createRequireRoles } from '../authorization/authorization.middleware.js'
import { createUserSearchController } from './user-search.controller.js'
import { createUserRolesController } from './user-roles.controller.js'

export function createUserSearchRouter({
  requireSession,
  authorizationService,
  userSearchService,
  userRolesService,
} = {}) {
  if (typeof requireSession !== 'function') {
    throw new TypeError('A session middleware is required')
  }
  const requireSystemAdmin = createRequireRoles({
    authorizationService,
    allowedRoles: ['system_admin'],
  })
  const controller = createUserSearchController({ userSearchService })
  const router = Router()

  router.use(requireSession, requireSystemAdmin)
  router.get('/', controller.searchUsers)
  if (userRolesService !== undefined) {
    const userRolesController = createUserRolesController({ userRolesService })
    router.get('/:userId/roles', userRolesController.getUserRoles)
  }
  return router
}
