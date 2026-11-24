const SECRET_PATTERN = /^[0-9a-f]{64}$/
const ENVIRONMENTS = new Set(['development', 'test', 'production'])
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])

function readSecret(env, name) {
    const value = env[name]

    if (
        typeof value !== 'string' ||
        !SECRET_PATTERN.test(value)
    ) {
        throw new TypeError(
            `${name} must contain 64 lowercase hex characters`
        )
    }

    return value
}

function readWebOrigin(value, environment) {
    if (typeof value !== 'string') {
        throw new TypeError('P32_WEB_ORIGIN is required')
    }

    let url

    try {
        url = new URL(value)
    } catch {
        throw new TypeError('P32_WEB_ORIGIN must be a valid origin')
    }

    if (
        !['http:', 'https:'].includes(url.protocol) ||
        value !== url.origin
    ) {
        throw new TypeError(
            'P32_WEB_ORIGIN must contain only a canonical HTTP(S) origin'
        )
    }

    const secure = url.protocol === 'https:'

    if (
        !secure &&
        (
            environment === 'production' ||
            !LOOPBACK_HOSTS.has(url.hostname)
        )
    ) {
        throw new TypeError(
            'HTTP is allowed only for local development or tests'
        )
    }

    return url
}

export function readAuthConfig(env) {
    if (!env || typeof env !== 'object' || Array.isArray(env)) {
        throw new TypeError('An environment settings object is required')
    }

    const environment = env.NODE_ENV

    if (!ENVIRONMENTS.has(environment)) {
        throw new TypeError(
            'NODE_ENV must be development, test or production'
        )
    }

    const jwtSecretHex = readSecret(env, 'P32_JWT_SECRET_HEX')
    const csrfSecretHex = readSecret(env, 'P32_CSRF_SECRET_HEX')

    if (jwtSecretHex === csrfSecretHex) {
        throw new TypeError('JWT and CSRF secrets must be different')
    }

    const origin = readWebOrigin(env.P32_WEB_ORIGIN, environment)
    const secure = origin.protocol === 'https:'

    return {
        environment,
        jwtSecretHex,
        csrfSecretHex,
        webOrigin: origin.origin,
        cookie: {
            name: secure ? '__Host-p32_session' : 'p32_session_dev',
            options: {
                httpOnly: true,
                secure,
                sameSite: 'lax',
                path: '/',
            },
        },
    }
}