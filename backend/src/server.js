import { once } from 'node:events'
import { randomBytes } from 'node:crypto'
import { createApp } from './app.js'
import { createAuthorizationRepository } from './modules/authorization/authorization.repository.js'
import { createAuthorizationService } from './modules/authorization/authorization.service.js'
import { createRoleRepository } from './modules/roles/roles.repository.js'
import { createRoleService } from './modules/roles/roles.service.js'
import { createRoleChangeRuntimeRepository } from './modules/roles/role-change.runtime.repository.js'
import { createRoleChangeService } from './modules/roles/role-change.service.js'
import { createUserSearchRuntimeRepository } from './modules/users/user-search.runtime.repository.js'
import { createUserSearchService } from './modules/users/user-search.service.js'
import { createUserRolesRuntimeRepository } from './modules/users/user-roles.runtime.repository.js'
import { createUserRolesService } from './modules/users/user-roles.service.js'
import { readAuthConfig } from './config/auth.config.js'
import { createJwtService } from './security/jwt.js'
import { createSessionCookie } from './modules/auth/session.cookie.js'
import { createSessionRepository } from './modules/auth/session.repository.js'
import { createSessionAuthService } from './modules/auth/session-auth.service.js'
import { createRequireSession } from './modules/auth/auth.middleware.js'
import { createCsrfProtection } from './security/csrf.js'
import { createSessionService } from './modules/auth/session.service.js'
import { createLoginCsrfProtection } from './security/login-csrf.js'
import { createLoginCsrfCookie } from './modules/auth/login-csrf.cookie.js'
import { createAuthRepository } from './modules/auth/auth.repository.js'
import { createAuthService } from './modules/auth/auth.service.js'
import { hashPassword } from './security/password.js'

const port = 3001
let databasePool

try {
    // ตรวจค่าตั้งก่อนโหลด pool และเปิดรับคำขอ
    const authConfig = readAuthConfig(process.env)

    const { pool } = await import('./database/pool.js')
    databasePool = pool

    const authRepository = createAuthRepository(pool)
    // สร้างเพียงครั้งเดียว เพื่อใช้ตรวจแบบเดียวกันเมื่อไม่พบชื่อบัญชี
    const dummyPasswordHash = await hashPassword(randomBytes(32).toString('hex'))
    const authService = createAuthService({
        findUserByUsername: authRepository.findUserByUsername,
        dummyPasswordHash,
    })
    const sessionRepository = createSessionRepository(pool)

    const sessionService = createSessionService({
        sessionRepository,
        csrfProtection: createCsrfProtection(authConfig.csrfSecretHex),
    })

    const jwtService = createJwtService({
        secretHex: authConfig.jwtSecretHex,
    })

    const sessionCookie = createSessionCookie(authConfig.cookie)
    const loginCsrfProtection = createLoginCsrfProtection({
        secretHex: authConfig.csrfSecretHex,
    })
    const loginCsrfCookie = createLoginCsrfCookie(authConfig.cookie.options)

    const sessionAuthService = createSessionAuthService({
        jwtService,
        sessionRepository,
    })

    const requireSession = createRequireSession({
        sessionCookie,
        sessionAuthService,
    })

    const authorizationRepository = createAuthorizationRepository(pool)
    const authorizationService = createAuthorizationService({ authorizationRepository })
    const roleRepository = createRoleRepository(pool)
    const roleService = createRoleService({ roleRepository })
    const roleChangeRepository = createRoleChangeRuntimeRepository(pool)
    const roleChangeService = createRoleChangeService({ roleChangeRepository })
    const userSearchRepository = createUserSearchRuntimeRepository(pool)
    const userSearchService = createUserSearchService({ userSearchRepository })
    const userRolesRepository = createUserRolesRuntimeRepository(pool)
    const userRolesService = createUserRolesService({ userRolesRepository })

    const app = createApp({
        authorizationService,
        roleService,
        roleChangeService,
        userSearchService,
        userRolesService,
        webOrigin: authConfig.webOrigin,
        requireSession,
        authService,
        jwtService,
        sessionService,
        sessionRepository,
        sessionCookie,
        loginCsrfProtection,
        loginCsrfCookie,
    })

    const server = app.listen(port, '127.0.0.1')

    // หากเปิดพอร์ตไม่สำเร็จ จะเข้า catch
    await once(server, 'listening')

    console.log(`P32 API is running at http://127.0.0.1:${port}`)
} catch (error) {
    const message = error instanceof TypeError
        ? error.message
        : 'Unexpected startup error'

    console.error('P32 startup failed:', message)
    process.exitCode = 1

    if (databasePool) {
        await databasePool.end().catch(() => {
            console.error('P32 database pool cleanup failed')
        })
    }
}
