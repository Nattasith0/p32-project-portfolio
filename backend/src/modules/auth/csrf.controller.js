export function createCsrfController({ sessionService }) {
    if (typeof sessionService?.getCsrfToken !== 'function') {
        throw new TypeError('A session service is required')
    }

    // ต้องผ่าน requestContext และ requireSession ก่อนเรียก
    async function getCsrfToken(request, response) {
        response.set('Cache-Control', 'no-store')

        const csrfToken = await sessionService.getCsrfToken({
            sessionId: request.auth.sessionId,
            userId: request.auth.userId,
        })

        if (!csrfToken) {
            response.set('WWW-Authenticate', 'Session realm="P32"')

            return response.status(401).json({
                code: 'AUTH_REQUIRED',
                message: 'กรุณาเข้าสู่ระบบ',
                request_id: request.requestId,
            })
        }

        return response.status(200).json({
            csrfToken,
        })
    }

    return { getCsrfToken }
}