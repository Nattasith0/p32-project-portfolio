import { Router } from 'express'
import { createRequireRoles } from '../authorization/authorization.middleware.js'
import { createRoleController } from './roles.controller.js'

export function createRoleRouter({
  requireSession,
  authorizationService,
  roleService,
} = {}) {
  if (typeof requireSession !== 'function') {
    throw new TypeError('A session middleware is required')
  }

  const requireSystemAdmin = createRequireRoles({
    authorizationService,
    allowedRoles: ['system_admin'],
  })
  const controller = createRoleController({ roleService })
  const router = Router()

  // ทุกเส้นทางในโมดูลจัดการบทบาทต้องผ่านสองชั้นนี้
  router.use(requireSession, requireSystemAdmin)
  router.get('/', controller.getRoles)

  return router
}
