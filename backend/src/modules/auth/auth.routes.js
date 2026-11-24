import { Router } from 'express'
import { getCurrentUser } from './auth.controller.js'
import { createCsrfController } from './csrf.controller.js'
import { createRequireCsrf } from './csrf.middleware.js'
import { createLogoutController } from './logout.controller.js'
import { createLoginCsrfController } from './login-csrf.controller.js'
import { createLoginController } from './login.controller.js'
import { createRequireLoginCsrf } from './login-csrf.middleware.js'
import { createLoginRateLimiter } from './login-rate-limit.middleware.js'
import { createLoginAccountRateLimiter } from './login-account-rate-limit.middleware.js'
import { createLoginJsonParser, validateLoginRequest } from './login-input.middleware.js'

export function createAuthRouter({
    requireSession,
    authService,
    jwtService,
    sessionService,
    sessionRepository,
    sessionCookie,
    loginCsrfProtection,
    loginCsrfCookie,
    logger = console,
}) {
    if (typeof requireSession !== 'function') {
        throw new TypeError('A session middleware is required')
    }

    const csrfController = createCsrfController({ sessionService })
    const requireCsrf = createRequireCsrf({ sessionService })
    const logoutController = createLogoutController({
        sessionRepository,
        sessionCookie,
    })

    const loginCsrfController = createLoginCsrfController({
        loginCsrfProtection,
        loginCsrfCookie,
    })

    const loginController = createLoginController({
        authService,
        sessionService,
        jwtService,
        sessionRepository,
        sessionCookie,
        loginCsrfCookie,
        logger,
    })
    const requireLoginCsrf = createRequireLoginCsrf({
        loginCsrfProtection,
        loginCsrfCookie,
    })
    // สร้าง limiter แต่ละตัวครั้งเดียวต่อ router ใช้ MemoryStore แยกกัน
    const loginRateLimiter = createLoginRateLimiter()
    const loginAccountRateLimiter = createLoginAccountRateLimiter()
    const loginJsonParser = createLoginJsonParser()

    const router = Router()

    // ผู้ใช้ต้องขอ challenge ได้ก่อนมี authenticated session
    router.get('/login-csrf', loginCsrfController.getLoginCsrf)

    router.post(
        '/login',
        loginRateLimiter,
        requireLoginCsrf,
        loginJsonParser,
        validateLoginRequest,
        loginAccountRateLimiter,
        loginController.login,
    )

    router.get('/me', requireSession, getCurrentUser)
    router.get('/csrf', requireSession, csrfController.getCsrfToken)

    router.post(
        '/logout',
        requireSession,
        requireCsrf,
        logoutController.logout,
    )

    return router
}