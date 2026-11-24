import test from 'node:test'
import assert from 'node:assert/strict'
import { readAuthConfig } from '../src/config/auth.config.js'

// กุญแจสมมติสำหรับ tests เท่านั้น
function validEnv(overrides = {}) {
    return {
        NODE_ENV: 'development',
        P32_JWT_SECRET_HEX: '11'.repeat(32),
        P32_CSRF_SECRET_HEX: '22'.repeat(32),
        P32_WEB_ORIGIN: 'http://localhost:5173',
        ...overrides,
    }
}

test('reads development config without modifying its input', () => {
    const env = Object.freeze(validEnv())
    const before = { ...env }

    assert.deepEqual(readAuthConfig(env), {
        environment: 'development',
        jwtSecretHex: '11'.repeat(32),
        csrfSecretHex: '22'.repeat(32),
        webOrigin: 'http://localhost:5173',
        cookie: {
            name: 'p32_session_dev',
            options: {
                httpOnly: true,
                secure: false,
                sameSite: 'lax',
                path: '/',
            },
        },
    })

    assert.deepEqual(env, before)
})

test('allows local HTTP in development and test environments', () => {
    for (const environment of ['development', 'test']) {
        for (const host of ['localhost', '127.0.0.1', '[::1]']) {
            const origin = `http://${host}:5173`

            const config = readAuthConfig(validEnv({
                NODE_ENV: environment,
                P32_WEB_ORIGIN: origin,
            }))

            assert.equal(config.environment, environment)
            assert.equal(config.webOrigin, origin)
            assert.equal(config.cookie.name, 'p32_session_dev')
            assert.equal(config.cookie.options.secure, false)
        }
    }
})

test('requires secure host-only cookie settings for production HTTPS', () => {
    const config = readAuthConfig(validEnv({
        NODE_ENV: 'production',
        P32_WEB_ORIGIN: 'https://p32.example.test',
    }))

    assert.equal(config.webOrigin, 'https://p32.example.test')
    assert.deepEqual(config.cookie, {
        name: '__Host-p32_session',
        options: {
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
            path: '/',
        },
    })

    assert.equal(Object.hasOwn(config.cookie.options, 'domain'), false)
})

test('also enables Secure cookies for HTTPS in development and test', () => {
    for (const environment of ['development', 'test']) {
        const config = readAuthConfig(validEnv({
            NODE_ENV: environment,
            P32_WEB_ORIGIN: 'https://p32.example.test',
        }))

        assert.equal(config.cookie.name, '__Host-p32_session')
        assert.equal(config.cookie.options.secure, true)
    }
})

test('rejects missing or invalid environment settings', () => {
    for (const invalid of [undefined, null, [], 123, 'settings', true]) {
        assert.throws(() => readAuthConfig(invalid), TypeError)
    }

    for (const invalid of [
        undefined, null, '', 'staging', 'Development', false, 123,
    ]) {
        assert.throws(() => readAuthConfig(validEnv({
            NODE_ENV: invalid,
        })), TypeError)
    }
})

test('rejects malformed JWT and CSRF secrets', () => {
    const invalidSecrets = [
        undefined,
        null,
        123,
        '',
        '11'.repeat(31),
        '11'.repeat(33),
        'zz'.repeat(32),
        'AB'.repeat(32),
        '11'.repeat(32) + '\n',
        '11'.repeat(32) + ' ',
    ]

    for (const name of [
        'P32_JWT_SECRET_HEX',
        'P32_CSRF_SECRET_HEX',
    ]) {
        for (const invalid of invalidSecrets) {
            assert.throws(() => readAuthConfig(validEnv({
                [name]: invalid,
            })), TypeError)
        }
    }
})

test('rejects using the same secret for JWT and CSRF', () => {
    assert.throws(() => readAuthConfig(validEnv({
        P32_CSRF_SECRET_HEX: '11'.repeat(32),
    })), {
        name: 'TypeError',
        message: 'JWT and CSRF secrets must be different',
    })
})

test('rejects malformed or non-canonical origins', () => {
    const invalidOrigins = [
        undefined,
        null,
        123,
        '',
        '*',
        'null',
        'localhost:5173',
        'ftp://localhost',
        'http://localhost:5173/',
        'http://localhost:5173/path',
        'http://localhost:5173?x=1',
        'http://localhost:5173#section',
        'http://user:example@localhost:5173',
        'http://LOCALHOST:5173',
        'http://localhost:80',
        'http://localhost:65536',
        ' http://localhost:5173',
        'http://localhost:5173\n',
    ]

    for (const origin of invalidOrigins) {
        assert.throws(() => readAuthConfig(validEnv({
            P32_WEB_ORIGIN: origin,
        })), TypeError)
    }
})

test('rejects non-local HTTP in development and test', () => {
    const remoteOrigins = [
        'http://p32.example.test',
        'http://localhost.example.test',
        'http://127.0.0.1.example.test',
        'http://192.168.1.10:5173',
        'http://0.0.0.0:5173',
    ]

    for (const environment of ['development', 'test']) {
        for (const origin of remoteOrigins) {
            assert.throws(() => readAuthConfig(validEnv({
                NODE_ENV: environment,
                P32_WEB_ORIGIN: origin,
            })), TypeError)
        }
    }
})

test('rejects all HTTP origins in production including loopback', () => {
    for (const origin of [
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'http://[::1]:5173',
        'http://p32.example.test',
    ]) {
        assert.throws(() => readAuthConfig(validEnv({
            NODE_ENV: 'production',
            P32_WEB_ORIGIN: origin,
        })), TypeError)
    }
})