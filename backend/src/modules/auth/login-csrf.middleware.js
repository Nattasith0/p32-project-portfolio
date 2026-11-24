export function createRequireLoginCsrf({
    loginCsrfCookie,
    loginCsrfProtection,
}) {
    if (typeof loginCsrfCookie?.readChallengeCookie !== 'function') {
        throw new TypeError('A login CSRF cookie reader is required')
    }

    if (typeof loginCsrfProtection?.verifyChallenge !== 'function') {
        throw new TypeError('Login CSRF verification is required')
    }

    // ใช้หลัง requestContext และ Origin check ก่อนตรวจ credentials
    return function requireLoginCsrf(request, response, next) {
        response.set('Cache-Control', 'no-store')

        const cookieValue = loginCsrfCookie.readChallengeCookie(
            request.headers.cookie
        )
        const csrfToken = request.headers['x-csrf-token']

        // Helper รับผิดชอบตรวจรูปแบบ ลายเซ็น และเวลาหมดอายุ
        const verified = loginCsrfProtection.verifyChallenge({
            cookieValue,
            csrfToken,
        })

        if (verified !== true) {
            return response.status(403).json({
                code: 'CSRF_INVALID',
                message: 'ไม่สามารถยืนยันคำขอได้',
                request_id: request.requestId,
            })
        }

        return next()
    }
}