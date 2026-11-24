import type { LoginInput, User } from '../types/auth'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

type AuthErrorDetails = {
    status: number
    code: string
    requestId: string | null
    retryAfter: number | null
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export class AuthApiError extends Error {
    readonly status: number
    readonly code: string
    readonly requestId: string | null
    readonly retryAfter: number | null
    constructor({ status, code, requestId, retryAfter }: AuthErrorDetails) {
        super('Authentication request failed')
        this.name = 'AuthApiError'
        this.status = status
        this.code = code
        this.requestId = requestId
        this.retryAfter = retryAfter
    }
}

async function readAuthError(response: Response) {
    let data: unknown = null

    try {
        data = await response.json()
    } catch {
        // Proxy อาจตอบ error ที่ไม่ใช่ JSON
    }

    const code = isRecord(data) && typeof data.code === 'string' && data.code === data.code.trim() && /^[A-Z][A-Z0-9_]{0,63}$/.test(data.code)
        ? data.code
        : 'AUTH_REQUEST_FAILED'

    const requestId = response.headers.get('x-request-id')
    const retryHeader = response.headers.get('retry-after')

    const retrySeconds = retryHeader !== null && /^\d+$/.test(retryHeader)
        ? Number(retryHeader)
        : NaN

    return new AuthApiError({
        status: response.status,
        code,
        requestId: requestId?.length === 36 && UUID_PATTERN.test(requestId)
            ? requestId
            : null,
        retryAfter: Number.isSafeInteger(retrySeconds) && retrySeconds > 0
            ? retrySeconds
            : null,
    })
}

function readUser(data: unknown): User {
    const user = isRecord(data) ? data.user : undefined

    if (
        !isRecord(user) ||
        typeof user.userId !== 'string' ||
        typeof user.username !== 'string' ||
        typeof user.displayName !== 'string'
    ) {
        throw new Error('Invalid current user response')
    }

    return {
        userId: user.userId,
        username: user.username,
        displayName: user.displayName,
    }
}

export async function getCurrentUser(signal?: AbortSignal): Promise<User | null> {
    const response = await fetch('/api/v1/auth/me', {
        signal,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: { Accept: 'application/json' },
    })

    if (response.status === 401) return null
    if (!response.ok) throw new Error('Current user request failed')

    return readUser(await response.json())
}

async function getLoginChallenge(signal?: AbortSignal): Promise<string> {
    const response = await fetch('/api/v1/auth/login-csrf', {
        signal,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: { Accept: 'application/json' },
    })

    if (!response.ok) throw await readAuthError(response)

    const data: unknown = await response.json()

    if (
        !isRecord(data) ||
        typeof data.csrfToken !== 'string' ||
        data.csrfToken.length === 0 ||
        data.csrfToken.length > 64 ||
        data.csrfToken !== data.csrfToken.trim() ||
        !/^[A-Za-z0-9._-]+$/.test(data.csrfToken)
    ) {
        throw new Error('Invalid login challenge response')
    }

    return data.csrfToken
}

export async function login({ username, password }: LoginInput, signal?: AbortSignal): Promise<User> {
    if (typeof username !== 'string' || typeof password !== 'string') {
        throw new TypeError('Username and password must be strings')
    }

    // ขอ challenge ใหม่เมื่อส่งฟอร์ม ไม่เก็บไว้ตั้งแต่เปิดหน้า
    const csrfToken = await getLoginChallenge(signal)

    const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        signal,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ username, password }),
    })

    if (!response.ok) throw await readAuthError(response)

    return readUser(await response.json())
}

export async function getSessionCsrfToken(signal?: AbortSignal): Promise<string | null> {
    const csrfResponse = await fetch('/api/v1/auth/csrf', {
        signal,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: { Accept: 'application/json' },
    })

    if (csrfResponse.status === 401) return null
    if (csrfResponse.status !== 200) {
        throw await readAuthError(csrfResponse)
    }

    const data: unknown = await csrfResponse.json()

    if (
        !isRecord(data) ||
        typeof data.csrfToken !== 'string' ||
        data.csrfToken.length !== 43 ||
        !/^[A-Za-z0-9_-]{43}$/.test(data.csrfToken)
    ) {
        throw new Error('Invalid session CSRF response')
    }

    return data.csrfToken
}

export async function logout(signal?: AbortSignal): Promise<void> {
    const csrfToken = await getSessionCsrfToken(signal)
    if (csrfToken === null) return

    const response = await fetch('/api/v1/auth/logout', {
        method: 'POST',
        signal,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: {
            Accept: 'application/json',
            'X-CSRF-Token': csrfToken,
        },
    })

    // 204 ไม่มี JSON; 401 หมายถึง session ใช้งานไม่ได้แล้ว
    if (response.status === 204 || response.status === 401) return

    throw await readAuthError(response)
}