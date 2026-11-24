import { createHash } from 'node:crypto'
import { rateLimit } from 'express-rate-limit'

export function createLoginAccountRateLimiter({
    windowMs = 60_000,
    limit = 5,
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
        identifier: 'p32-login-account',
        standardHeaders: 'draft-8',
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        skipFailedRequests: false,
        passOnStoreError: false,

        keyGenerator(request) {
            const username = request.loginInput?.username

            // ต้องวางหลัง validateLoginRequest และไม่อ่านชื่อบัญชีจาก query
            if (
                typeof username !== 'string' ||
                username.length === 0 ||
                Array.from(username).length > 128 ||
                username !== username.trim().toLowerCase()
            ) {
                throw new TypeError('Validated login input is required')
            }

            // ไม่ใส่ชื่อบัญชีดิบใน key; ไม่ใช้ IP หรือรหัสผ่านเป็นส่วนของ key
            const digest = createHash('sha256')
                .update(JSON.stringify(['P32-LOGIN-ACCOUNT-v1', username]))
                .digest('hex')

            return `p32-login-account:${digest}`
        },

        handler(request, response) {
            return response.status(429).json({
                code: 'LOGIN_RATE_LIMITED',
                message: 'มีคำขอเข้าสู่ระบบมากเกินไป กรุณาลองใหม่ภายหลัง',
                request_id: request.requestId,
            })
        },
    })

    // สร้างครั้งเดียว โดยใช้ store คนละ instance กับ IP limiter
    return function loginAccountRateLimiter(request, response, next) {
        response.set('Cache-Control', 'no-store')
        return limiter(request, response, next)
    }
}
