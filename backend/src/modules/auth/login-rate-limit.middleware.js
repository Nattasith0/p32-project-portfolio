import { rateLimit } from 'express-rate-limit'

export function createLoginRateLimiter({
    windowMs = 60_000,
    limit = 60,
    store,
} = {}) {
    if (
        !Number.isSafeInteger(windowMs) ||
        windowMs < 1 ||
        windowMs > 2_147_483_647
    ) {
        throw new TypeError('A valid rate limit window is required')
    }

    if (!Number.isSafeInteger(limit) || limit < 1) {
        throw new TypeError('A positive integer request limit is required')
    }

    if (store !== undefined) {
        for (const method of ['increment', 'decrement', 'resetKey']) {
            if (typeof store?.[method] !== 'function') {
                throw new TypeError('A compatible rate limit store is required')
            }
        }
    }

    const limiter = rateLimit({
        windowMs,
        limit,
        store,
        ipv6Subnet: 56,
        identifier: 'p32-login-ip',
        standardHeaders: 'draft-8',
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        skipFailedRequests: false,
        passOnStoreError: false,

        handler(request, response) {
            return response.status(429).json({
                code: 'LOGIN_RATE_LIMITED',
                message: 'มีคำขอเข้าสู่ระบบมากเกินไป กรุณาลองใหม่ภายหลัง',
                request_id: request.requestId,
            })
        },
    })

    // สร้างครั้งเดียวตอนประกอบ app ไม่สร้างใหม่สำหรับแต่ละคำขอ
    return function loginRateLimiter(request, response, next) {
        response.set('Cache-Control', 'no-store')
        return limiter(request, response, next)
    }
}
