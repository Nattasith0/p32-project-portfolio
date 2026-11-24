import { parseCookie } from 'cookie'

const MAX_COOKIE_HEADER_BYTES = 8192
const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/

function isNonce(value) {
    return typeof value === 'string' &&
        value.length === 43 && NONCE_PATTERN.test(value)
}

export function createLoginCsrfCookie(cookieOptions) {
    if (
        typeof cookieOptions?.secure !== 'boolean' ||
        cookieOptions.httpOnly !== true ||
        cookieOptions.sameSite !== 'lax' ||
        cookieOptions.path !== '/' ||
        Object.hasOwn(cookieOptions, 'domain')
    ) {
        throw new TypeError('Validated cookie options are required')
    }

    const name = cookieOptions.secure
        ? '__Host-p32_login_csrf'
        : 'p32_login_csrf_dev'

    // คัดเฉพาะค่าที่อนุญาต ไม่อ้าง object จากภายนอกในครั้งถัดไป
    const baseOptions = {
        httpOnly: true,
        secure: cookieOptions.secure,
        sameSite: 'lax',
        path: '/',
    }

    function readChallengeCookie(cookieHeader) {
        if (
            typeof cookieHeader !== 'string' ||
            cookieHeader.length === 0 ||
            Buffer.byteLength(cookieHeader, 'utf8') > MAX_COOKIE_HEADER_BYTES
        ) {
            return null
        }

        let cookieValue = null

        for (const part of cookieHeader.split(';')) {
            const parsed = parseCookie(part)
            if (!Object.hasOwn(parsed, name)) continue

            // ปฏิเสธชื่อ challenge cookie ซ้ำ แม้ค่าจะเหมือนกัน
            if (cookieValue !== null) return null
            if (!isNonce(parsed[name])) return null

            cookieValue = parsed[name]
        }

        return cookieValue
    }

    function setChallengeCookie(response, { cookieValue, expiresAt }) {
        if (typeof response?.cookie !== 'function') {
            throw new TypeError('An Express response is required')
        }

        if (!isNonce(cookieValue)) {
            throw new TypeError('A login CSRF cookie value is required')
        }

        const expirationMs = expiresAt instanceof Date
            ? expiresAt.getTime()
            : NaN

        if (
            !Number.isSafeInteger(expirationMs) ||
            expirationMs < 0 ||
            expirationMs % 1000 !== 0
        ) {
            throw new TypeError('A whole-second expiration Date is required')
        }

        return response.cookie(name, cookieValue, {
            ...baseOptions,
            expires: new Date(expirationMs),
        })
    }

    function clearChallengeCookie(response) {
        if (typeof response?.clearCookie !== 'function') {
            throw new TypeError('An Express response is required')
        }

        return response.clearCookie(name, { ...baseOptions })
    }

    return {
        readChallengeCookie,
        setChallengeCookie,
        clearChallengeCookie,
    }
}
