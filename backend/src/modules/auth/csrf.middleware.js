import { timingSafeEqual } from 'node:crypto'

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/

function isCsrfToken(value) {
    return typeof value === 'string' &&
        value.length === 43 && TOKEN_PATTERN.test(value)
}

export function createRequireCsrf({ sessionService }) {
    if (typeof sessionService?.getCsrfToken !== 'function') {
        throw new TypeError('A session service is required')
    }

    function rejectCsrf(request, response) {
        return response.status(403).json({
            code: 'CSRF_INVALID',
            message: 'ไม่สามารถยืนยันคำขอได้',
            request_id: request.requestId,
        })
    }

    // ใช้กับคำขอเปลี่ยนข้อมูล หลัง requestContext และ requireSession
    return async function requireCsrf(request, response, next) {
        response.set('Cache-Control', 'no-store')

        const token = request.headers['x-csrf-token']

        // ตรวจรูปแบบก่อนเรียก service
        if (!isCsrfToken(token)) {
            return rejectCsrf(request, response)
        }

        const expectedToken = await sessionService.getCsrfToken({
            sessionId: request.auth.sessionId,
            userId: request.auth.userId,
        })

        if (expectedToken === null) {
            response.set('WWW-Authenticate', 'Session realm="P32"')

            return response.status(401).json({
                code: 'AUTH_REQUIRED',
                message: 'กรุณาเข้าสู่ระบบ',
                request_id: request.requestId,
            })
        }

        // ผลจาก service ต้องตรงตาม contract
        if (!isCsrfToken(expectedToken)) {
            throw new TypeError('Invalid CSRF token from session service')
        }

        const matches = timingSafeEqual(
            Buffer.from(token, 'utf8'),
            Buffer.from(expectedToken, 'utf8'),
        )

        if (!matches) {
            return rejectCsrf(request, response)
        }

        return next()
    }
}