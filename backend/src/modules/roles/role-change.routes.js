import { Router } from 'express'
import { createRequireOrigin } from '../../middleware/origin.middleware.js'
import { createJsonBodyParser } from '../../middleware/json-body.middleware.js'
import { createRequireRoles } from '../authorization/authorization.middleware.js'
import { createRequireCsrf } from '../auth/csrf.middleware.js'
import { createRoleChangeController } from './role-change.controller.js'

export function createRoleChangeRouter({
  webOrigin,
  requireSession,
  authorizationService,
  sessionService,
  roleChangeService,
} = {}) {
  if (typeof requireSession !== 'function') {
    throw new TypeError('A session middleware is required')
  }

  const requireOrigin = createRequireOrigin({ webOrigin })
  const requireSystemAdmin = createRequireRoles({
    authorizationService,
    allowedRoles: ['system_admin'],
  })
  const requireCsrf = createRequireCsrf({ sessionService })
  const parseJson = createJsonBodyParser()
  const controller = createRoleChangeController({ roleChangeService })
  const router = Router()

  // requestContext ต้องอยู่ก่อน router; ตรวจสิทธิ์ก่อนอ่าน body/เริ่ม transaction
  router.post(
    '/',
    requireOrigin,
    requireSession,
    requireSystemAdmin,
    requireCsrf,
    parseJson,
    controller.changeUserRole,
  )

  return router
}
