export function createRequireSession({
    sessionCookie,
    sessionAuthService,
}) {
    if (typeof sessionCookie?.readSessionToken !== 'function') {
        throw new TypeError('A session cookie reader is required')
    }

    if (
        typeof sessionAuthService?.authenticateSessionToken !== 'function'
    ) {
        throw new TypeError('A session authentication service is required')
    }

    function rejectUnauthorized(request, response) {
        response.set('WWW-Authenticate', 'Session realm="P32"')

        return response.status(401).json({
            code: 'AUTH_REQUIRED',
            message: 'กรุณาเข้าสู่ระบบ',
            request_id: request.requestId,
        })
    }

    // ต้องวาง requestContext ก่อน middleware นี้
    return async function requireSession(request, response, next) {
        request.auth = null
        response.set('Cache-Control', 'no-store')

        const token = sessionCookie.readSessionToken(
            request.headers.cookie
        )

        if (!token) {
            return rejectUnauthorized(request, response)
        }

        const identity =
            await sessionAuthService.authenticateSessionToken(token)

        if (!identity) {
            return rejectUnauthorized(request, response)
        }

        request.auth = identity

        return next()
    }
}