import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

const SECRET_PATTERN = /^[0-9a-f]{64}$/
const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/
const EXPIRATION_PATTERN = /^[1-9][0-9]{0,12}$/
const LIFETIME_SECONDS = 10 * 60
const MAX_TOKEN_LENGTH = 64

function isNonce(value) {
    return typeof value === 'string' &&
        value.length === 43 && NONCE_PATTERN.test(value)
}

export function createLoginCsrfProtection({ secretHex, now = Date.now }) {
    if (
        typeof secretHex !== 'string' ||
        secretHex.length !== 64 ||
        !SECRET_PATTERN.test(secretHex)
    ) {
        throw new TypeError('Login CSRF secret must contain 64 lowercase hex characters')
    }

    if (typeof now !== 'function') {
        throw new TypeError('A clock function is required')
    }

    const key = Buffer.from(secretHex, 'hex')

    function readClockSeconds() {
        const milliseconds = now()

        if (
            !Number.isSafeInteger(milliseconds) ||
            milliseconds < 0 ||
            !Number.isFinite(new Date(milliseconds).getTime())
        ) {
            throw new TypeError('Invalid clock value')
        }

        return Math.floor(milliseconds / 1000)
    }

    function createSignature(cookieValue, expiresSeconds) {
        // แยกบริบทจาก token ของ authenticated session แม้ใช้ CSRF key เดียวกัน
        const message = JSON.stringify([
            'P32-LOGIN-CSRF-v1',
            cookieValue,
            expiresSeconds,
        ])

        return createHmac('sha256', key)
            .update(message)
            .digest('base64url')
    }

    function createChallenge() {
        const expiresSeconds = readClockSeconds() + LIFETIME_SECONDS
        const expiresAt = new Date(expiresSeconds * 1000)

        if (!Number.isFinite(expiresAt.getTime())) {
            throw new TypeError('Invalid login CSRF expiration')
        }

        const cookieValue = randomBytes(32).toString('base64url')
        const signature = createSignature(cookieValue, expiresSeconds)

        return {
            cookieValue,
            csrfToken: `${expiresSeconds}.${signature}`,
            expiresAt,
        }
    }

    function verifyChallenge(challenge) {
        if (!challenge || typeof challenge !== 'object' || Array.isArray(challenge)) {
            return false
        }

        const { cookieValue, csrfToken } = challenge

        if (
            !isNonce(cookieValue) ||
            typeof csrfToken !== 'string' ||
            csrfToken.length > MAX_TOKEN_LENGTH
        ) {
            return false
        }

        const parts = csrfToken.split('.')
        if (parts.length !== 2) return false

        const [expirationText, signature] = parts
        const expiresSeconds = Number(expirationText)

        if (
            !EXPIRATION_PATTERN.test(expirationText) ||
            !Number.isSafeInteger(expiresSeconds) ||
            String(expiresSeconds) !== expirationText ||
            !Number.isFinite(new Date(expiresSeconds * 1000).getTime()) ||
            !isNonce(signature)
        ) {
            return false
        }

        const currentSeconds = readClockSeconds()

        if (
            expiresSeconds <= currentSeconds ||
            expiresSeconds - currentSeconds > LIFETIME_SECONDS
        ) {
            return false
        }

        const expectedSignature = createSignature(cookieValue, expiresSeconds)

        return timingSafeEqual(
            Buffer.from(signature, 'utf8'),
            Buffer.from(expectedSignature, 'utf8'),
        )
    }

    return { createChallenge, verifyChallenge }
}
