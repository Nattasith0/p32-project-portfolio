import { randomUUID } from 'node:crypto'

const SESSION_LIFETIME_SECONDS = 30 * 60

export function createSessionService({
    sessionRepository,
    csrfProtection,
    now = Date.now,
}) {
    if (
        typeof sessionRepository?.createSession !== 'function' ||
        typeof sessionRepository?.findActiveSession !== 'function'
    ) {
        throw new TypeError('A session repository is required')
    }

    if (
        typeof csrfProtection?.createToken !== 'function' ||
        typeof csrfProtection?.hashToken !== 'function' ||
        typeof csrfProtection?.verifyToken !== 'function'
    ) {
        throw new TypeError('CSRF protection is required')
    }

    if (typeof now !== 'function') {
        throw new TypeError('A clock function is required')
    }

    // userId ต้องมาจากผลตรวจ credentials ภายใน Backend
    async function startSession({ userId }) {
        const sessionId = randomUUID()
        const context = { sessionId, userId }

        const csrfToken = csrfProtection.createToken(context)
        const csrfTokenHash = csrfProtection.hashToken(csrfToken)

        const currentTime = now()

        if (!Number.isSafeInteger(currentTime) || currentTime < 0) {
            throw new TypeError('Invalid clock value')
        }

        // ใช้ความละเอียดระดับวินาที เพื่อเตรียมให้ตรงกับ JWT ภายหลัง
        const issuedAtSeconds = Math.floor(currentTime / 1000)
        const expiresAt = new Date(
            (issuedAtSeconds + SESSION_LIFETIME_SECONDS) * 1000
        )

        if (!Number.isFinite(expiresAt.getTime())) {
            throw new TypeError('Invalid session expiration')
        }

        const session = await sessionRepository.createSession({
            sessionId,
            userId,
            csrfTokenHash,
            expiresAt,
        })

        return {
            sessionId: session.session_id,
            userId: session.user_id,
            expiresAt: session.expires_at,
        }
    }

    // ใช้ sessionId/userId จากข้อมูลยืนยันตัวตนที่ Backend ตรวจแล้ว
    async function getCsrfToken({ sessionId, userId }) {
        const active = await sessionRepository.findActiveSession({
            sessionId,
            userId,
        })

        if (!active) {
            return null
        }

        const token = csrfProtection.createToken({
            sessionId,
            userId,
        })

        const matches = csrfProtection.verifyToken(token, {
            sessionId: active.session_id,
            userId: active.user_id,
            csrfTokenHash: active.csrf_token_hash,
        })

        if (!matches) {
            return null
        }

        return token
    }

    return { startSession, getCsrfToken }
}
