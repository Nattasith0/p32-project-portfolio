import express from 'express'
import { healthRouter } from './modules/health/health.routes.js'
import { createAuthRouter } from './modules/auth/auth.routes.js'
import { createRoleRouter } from './modules/roles/roles.routes.js'
import { createRoleChangeRouter } from './modules/roles/role-change.routes.js'
import { createUserSearchRouter } from './modules/users/user-search.routes.js'
import { requestContext } from './middleware/request-context.middleware.js'
import { createApiErrorHandler } from './middleware/api-error.middleware.js'
import { createRequireOrigin } from './middleware/origin.middleware.js'

export function createApp({
    webOrigin,
    requireSession,
    authorizationService,
    roleService,
    roleChangeService,
    userSearchService,
    userRolesService,
    authService,
    jwtService,
    sessionService,
    sessionRepository,
    sessionCookie,
    loginCsrfProtection,
    loginCsrfCookie,
    logger = console,
}) {
    const app = express()

    app.disable('x-powered-by')

    // ทุกคำขอมี request ID ก่อนเข้า routes
    app.use(requestContext)

    app.use('/api/health', healthRouter)

    app.use(
        '/api/v1/auth',
        createRequireOrigin({ webOrigin }),
        createAuthRouter({
            requireSession,
            authService,
            jwtService,
            sessionService,
            sessionRepository,
            sessionCookie,
            loginCsrfProtection,
            loginCsrfCookie,
            logger,
        }),
    )

    app.use(
        '/api/v1/admin/roles',
        createRequireOrigin({ webOrigin }),
        createRoleRouter({ requireSession, authorizationService, roleService }),
    )

    app.use(
        '/api/v1/admin/users',
        createRequireOrigin({ webOrigin }),
        createUserSearchRouter({ requireSession, authorizationService, userSearchService, userRolesService }),
    )

    // Router นี้บังคับ Origin/session/system_admin/CSRF ก่อนอ่าน JSON ภายใน
    app.use(
        '/api/v1/admin/role-changes',
        createRoleChangeRouter({
            webOrigin,
            requireSession,
            authorizationService,
            sessionService,
            roleChangeService,
        }),
    )

    // ทำงานเมื่อไม่มี route ใดรับคำขอ
    app.use((request, response) => {
        response.set('Cache-Control', 'no-store')

        return response.status(404).json({
            code: 'NOT_FOUND',
            message: 'ไม่พบเส้นทางที่ร้องขอ',
            request_id: request.requestId,
        })
    })

    // Error handler ต้องอยู่หลัง routes
    app.use(createApiErrorHandler({ logger }))

    return app
}
