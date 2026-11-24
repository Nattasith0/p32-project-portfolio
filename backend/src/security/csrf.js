import {
    createHash,
    createHmac,
    timingSafeEqual,
} from 'node:crypto'

const HEX_256_PATTERN = /^[0-9a-f]{64}$/
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isUuid(value) {
    return typeof value === 'string' && UUID_PATTERN.test(value)
}

function isToken(value) {
    return typeof value === 'string' && TOKEN_PATTERN.test(value)
}

export function createCsrfProtection(secretHex) {
    if (
        typeof secretHex !== 'string' ||
        !HEX_256_PATTERN.test(secretHex)
    ) {
        throw new TypeError('CSRF secret must be 64 lowercase hex characters')
    }

    const key = Buffer.from(secretHex, 'hex')

    function createToken({ sessionId, userId }) {
        if (!isUuid(sessionId) || !isUuid(userId)) {
            throw new TypeError('CSRF context requires session and user UUIDs')
        }

        const message = JSON.stringify([
            'P32-CSRF-v1',
            sessionId.toLowerCase(),
            userId.toLowerCase(),
        ])

        return createHmac('sha256', key)
            .update(message)
            .digest('base64url')
    }

    function hashToken(token) {
        if (!isToken(token)) {
            throw new TypeError('Invalid CSRF token format')
        }

        return createHash('sha256').update(token).digest('hex')
    }

    function verifyToken(token, session) {
        if (
            !isToken(token) ||
            !session ||
            typeof session !== 'object' ||
            !isUuid(session.sessionId) ||
            !isUuid(session.userId) ||
            typeof session.csrfTokenHash !== 'string' ||
            !HEX_256_PATTERN.test(session.csrfTokenHash)
        ) {
            return false
        }

        const actual = Buffer.from(hashToken(token), 'hex')
        const stored = Buffer.from(session.csrfTokenHash, 'hex')
        const expected = Buffer.from(
            hashToken(createToken(session)),
            'hex'
        )

        const matchesStored = timingSafeEqual(actual, stored)
        const matchesContext = timingSafeEqual(actual, expected)

        return matchesStored && matchesContext
    }

    return { createToken, hashToken, verifyToken }
}