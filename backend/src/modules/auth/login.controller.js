export function createLoginController({
    authService,
    sessionService,
    jwtService,
    sessionRepository,
    sessionCookie,
    loginCsrfCookie,
    logger = console,
}) {
    for (const [dependency, method] of [
        [authService, 'authenticateCredentials'],
        [sessionService, 'startSession'],
        [jwtService, 'signSession'],
        [sessionRepository, 'revokeSession'],
        [sessionCookie, 'setSessionCookie'],
        [loginCsrfCookie, 'clearChallengeCookie'],
        [logger, 'error'],
    ]) {
        if (typeof dependency?.[method] !== 'function') {
            throw new TypeError('Invalid login controller dependencies')
        }
    }

    // ต้องผ่าน Origin, rate limits, login CSRF และ input validation ก่อนเรียก
    async function login(request, response) {
        response.set('Cache-Control', 'no-store')

        const input = request.loginInput
        if (typeof input?.username !== 'string' || typeof input.password !== 'string') {
            throw new TypeError('Validated login input is required')
        }

        const user = await authService.authenticateCredentials({
            username: input.username,
            password: input.password,
        })

        if (user === null) {
            response.set('WWW-Authenticate', 'Session realm="P32"')
            return response.status(401).json({
                code: 'INVALID_CREDENTIALS',
                message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง',
                request_id: request.requestId,
            })
        }

        const safeUser = {
            userId: user.userId,
            username: user.username,
            displayName: user.displayName,
        }
        const existingCookies = response.getHeader('Set-Cookie')
        const previousCookies = Array.isArray(existingCookies)
            ? [...existingCookies]
            : existingCookies
        let session

        try {
            // สร้าง session ใหม่ ไม่ใช้ session ID จาก client
            session = await sessionService.startSession({ userId: user.userId })
            const token = await jwtService.signSession(session)

            loginCsrfCookie.clearChallengeCookie(response)
            sessionCookie.setSessionCookie(response, {
                token,
                expiresAt: session.expiresAt,
            })

            return response.status(200).json({ user: safeUser })
        } catch (error) {
            // คืนเฉพาะ cookie headers ที่ยังไม่ถูกส่งให้ client
            if (!response.headersSent) {
                if (previousCookies === undefined) response.removeHeader('Set-Cookie')
                else response.setHeader('Set-Cookie', previousCookies)
            }

            if (session) {
                try {
                    await sessionRepository.revokeSession({
                        sessionId: session.sessionId,
                        userId: session.userId,
                    })
                } catch {
                    // การเพิกถอนเป็น best effort ไม่ใช่ database rollback
                    try {
                        logger.error('P32 login session cleanup failed', {
                            code: 'LOGIN_SESSION_CLEANUP_FAILED',
                            request_id: request.requestId,
                        })
                    } catch {
                        // คง error เดิมเพื่อให้ API error handler ตอบกลับอย่างปลอดภัย
                    }
                }
            }

            throw error
        }
    }

    return { login }
}
