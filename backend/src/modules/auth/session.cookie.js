import { parseCookie } from 'cookie'

const MAX_TOKEN_LENGTH = 4096
const MAX_COOKIE_HEADER_BYTES = 8192
const JWT_PATTERN =
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/

export function createSessionCookie(cookieConfig) {
    const { name, options } = cookieConfig ?? {}

    if (
        typeof options?.secure !== 'boolean' ||
        options.httpOnly !== true ||
        options.sameSite !== 'lax' ||
        options.path !== '/' ||
        name !== (
            options.secure ? '__Host-p32_session' : 'p32_session_dev'
        ) ||
        Object.hasOwn(options, 'domain')
    ) {
        throw new TypeError('Validated session cookie settings are required')
    }

    // ใช้เฉพาะค่าที่นโยบาย cookie อนุญาต
    const baseOptions = {
        httpOnly: true,
        secure: options.secure,
        sameSite: 'lax',
        path: '/',
    }

    function readSessionToken(cookieHeader) {
        if (
            typeof cookieHeader !== 'string' ||
            cookieHeader.length === 0 ||
            Buffer.byteLength(cookieHeader, 'utf8') > MAX_COOKIE_HEADER_BYTES
        ) {
            return null
        }

        let token = null

        for (const part of cookieHeader.split(';')) {
            const parsed = parseCookie(part)

            if (!Object.hasOwn(parsed, name)) {
                continue
            }

            // ปฏิเสธชื่อ session cookie ซ้ำ แม้ค่าจะเหมือนกัน
            if (token !== null) {
                return null
            }

            const value = parsed[name]

            if (
                typeof value !== 'string' ||
                value.length === 0 ||
                value.length > MAX_TOKEN_LENGTH ||
                !JWT_PATTERN.test(value)
            ) {
                return null
            }

            token = value
        }

        return token
    }

    function setSessionCookie(response, { token, expiresAt }) {
        if (typeof response?.cookie !== 'function') {
            throw new TypeError('An Express response is required')
        }

        if (
            typeof token !== 'string' ||
            token.length === 0 ||
            token.length > MAX_TOKEN_LENGTH
        ) {
            throw new TypeError('A session token is required')
        }

        const expirationMs =
            expiresAt instanceof Date ? expiresAt.getTime() : NaN

        if (
            !Number.isSafeInteger(expirationMs) ||
            expirationMs < 0 ||
            expirationMs % 1000 !== 0
        ) {
            throw new TypeError('A whole-second expiration Date is required')
        }

        return response.cookie(name, token, {
            ...baseOptions,
            expires: new Date(expirationMs),
        })
    }

    function clearSessionCookie(response) {
        if (typeof response?.clearCookie !== 'function') {
            throw new TypeError('An Express response is required')
        }

        return response.clearCookie(name, { ...baseOptions })
    }

    return {
        readSessionToken,
        setSessionCookie,
        clearSessionCookie,
    }
}