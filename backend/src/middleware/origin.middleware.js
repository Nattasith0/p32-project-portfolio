const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export function createRequireOrigin({ webOrigin }) {
    if (typeof webOrigin !== 'string') {
        throw new TypeError('A canonical web origin is required')
    }

    let parsedOrigin

    try {
        parsedOrigin = new URL(webOrigin)
    } catch {
        throw new TypeError('A canonical web origin is required')
    }

    if (
        !['http:', 'https:'].includes(parsedOrigin.protocol) ||
        parsedOrigin.origin !== webOrigin
    ) {
        throw new TypeError('A canonical web origin is required')
    }

    // webOrigin ต้องมาจากค่าตั้งที่ Backend ตรวจแล้ว
    return function requireOrigin(request, response, next) {
        if (SAFE_METHODS.has(request.method)) {
            return next()
        }

        response.set('Cache-Control', 'no-store')

        // เทียบเต็มค่า ไม่ใช้ startsWith หรือ includes
        if (request.headers.origin !== webOrigin) {
            return response.status(403).json({
                code: 'ORIGIN_NOT_ALLOWED',
                message: 'ไม่อนุญาตคำขอจากแหล่งที่มานี้',
                request_id: request.requestId,
            })
        }

        return next()
    }
}