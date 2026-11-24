import { randomUUID } from 'node:crypto'

const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const INVALID_JSON = {
    status: 400,
    code: 'INVALID_JSON',
    message: 'รูปแบบ JSON ไม่ถูกต้อง',
}

const INVALID_REQUEST = {
    status: 400,
    code: 'INVALID_REQUEST',
    message: 'ข้อมูลคำขอไม่ถูกต้อง',
}

const PAYLOAD_TOO_LARGE = {
    status: 413,
    code: 'PAYLOAD_TOO_LARGE',
    message: 'ข้อมูลคำขอมีขนาดเกินกำหนด',
}

const UNSUPPORTED_MEDIA_TYPE = {
    status: 415,
    code: 'UNSUPPORTED_MEDIA_TYPE',
    message: 'รูปแบบข้อมูลคำขอไม่รองรับ',
}

const INTERNAL_ERROR = {
    status: 500,
    code: 'INTERNAL_ERROR',
    message: 'เกิดข้อผิดพลาดภายในระบบ',
}

const PARSER_ERRORS = new Map([
    ['entity.parse.failed', INVALID_JSON],
    ['request.size.invalid', INVALID_REQUEST],
    ['entity.too.large', PAYLOAD_TOO_LARGE],
    ['charset.unsupported', UNSUPPORTED_MEDIA_TYPE],
    ['encoding.unsupported', UNSUPPORTED_MEDIA_TYPE],
])

function getPublicError(error) {
    const known = error instanceof Error
        ? PARSER_ERRORS.get(error.type)
        : undefined

    return known && error.status === known.status
        ? known
        : INTERNAL_ERROR
}

export function createApiErrorHandler({ logger = console } = {}) {
    if (typeof logger?.error !== 'function') {
        throw new TypeError('An error logger is required')
    }

    return function apiErrorHandler(error, request, response, next) {
        if (response.headersSent) {
            return next(error)
        }

        const requestId =
            typeof request.requestId === 'string' &&
                UUID_PATTERN.test(request.requestId)
                ? request.requestId
                : randomUUID()

        request.requestId = requestId

        response.set('X-Request-Id', requestId)
        response.set('Cache-Control', 'no-store')

        const failure = getPublicError(error)

        if (failure.status === 500) {
            try {
                logger.error('P32 API request failed', {
                    code: failure.code,
                    request_id: requestId,
                })
            } catch {
                // ส่งคำตอบที่ปลอดภัยต่อ แม้ logger ใช้งานไม่ได้
            }
        }

        return response.status(failure.status).json({
            code: failure.code,
            message: failure.message,
            request_id: requestId,
        })
    }
}