import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createApp } from '../src/app.js'
import { readAuthConfig } from '../src/config/auth.config.js'
import { createAuthRepository } from '../src/modules/auth/auth.repository.js'
import { createAuthService } from '../src/modules/auth/auth.service.js'
import { createSessionService } from '../src/modules/auth/session.service.js'
import { createSessionAuthService } from '../src/modules/auth/session-auth.service.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'
import { createCsrfProtection } from '../src/security/csrf.js'
import { createLoginCsrfProtection } from '../src/security/login-csrf.js'
import { createJwtService } from '../src/security/jwt.js'
import { hashPassword } from '../src/security/password.js'

// ใช้ crypto/Argon2/app/router จริง แต่จำลอง query executor และ session repository
// ไม่อ่าน .env และไม่เชื่อม PostgreSQL
const PASSWORD = ' TEST_ONLY_PASSWORD_123 '
const DUMMY_PASSWORD = 'TEST_ONLY_DUMMY_PASSWORD_123'
const passwordHash = await hashPassword(PASSWORD)
const dummyPasswordHash = await hashPassword(DUMMY_PASSWORD)
const FIXED_TIME = Date.parse('2026-11-03T03:00:00.987Z')
const config = readAuthConfig({
    NODE_ENV: 'test', P32_WEB_ORIGIN: 'http://localhost:5173',
    P32_JWT_SECRET_HEX: '33'.repeat(32), P32_CSRF_SECRET_HEX: '44'.repeat(32),
})
const safeUser = {
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    username: 'student_demo', displayName: 'ผู้ใช้ทดสอบ',
}
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

async function startFixture(t) {
    const stats = { lookups: [], logs: [], rows: new Map() }
    const users = [
        { user_id: safeUser.userId, username: safeUser.username, is_active: true, email_verified_at: new Date(FIXED_TIME) },
        { user_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', username: 'inactive_user', is_active: false, email_verified_at: new Date(FIXED_TIME) },
        { user_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', username: 'unverified_user', is_active: false, email_verified_at: null },
    ].map((user) => ({ ...user, display_name: safeUser.displayName, password_hash: passwordHash }))
    const authRepository = createAuthRepository({
        async query(sql, [username]) {
            stats.lookups.push(username)
            return { rows: users.filter((user) => user.username === username) }
        },
    })
    const authService = createAuthService({
        findUserByUsername: authRepository.findUserByUsername, dummyPasswordHash,
    })
    const repository = {
        async createSession(input) {
            const row = {
                session_id: input.sessionId, user_id: input.userId,
                expires_at: input.expiresAt, csrf_token_hash: input.csrfTokenHash,
                revoked_at: null,
            }
            stats.rows.set(row.session_id, row)
            return row
        },
        async findActiveSession({ sessionId, userId }) {
            const row = stats.rows.get(sessionId)
            const user = users.find((candidate) => candidate.user_id === userId)
            if (!row || row.user_id !== userId || row.revoked_at ||
                row.expires_at.getTime() <= FIXED_TIME || !user?.is_active || !user.email_verified_at) return null
            return { ...row, username: user.username, display_name: user.display_name }
        },
        async revokeSession({ sessionId, userId }) {
            const row = stats.rows.get(sessionId)
            if (!row || row.user_id !== userId || row.revoked_at) return false
            row.revoked_at = new Date(FIXED_TIME)
            return true
        },
    }
    const sessionService = createSessionService({
        sessionRepository: repository, csrfProtection: createCsrfProtection(config.csrfSecretHex), now: () => FIXED_TIME,
    })
    const jwtService = createJwtService({ secretHex: config.jwtSecretHex, now: () => FIXED_TIME })
    const sessionCookie = createSessionCookie(config.cookie)
    const loginCsrfProtection = createLoginCsrfProtection({ secretHex: config.csrfSecretHex, now: () => FIXED_TIME })
    const loginCsrfCookie = createLoginCsrfCookie(config.cookie.options)
    const requireSession = createRequireSession({
        sessionCookie,
        sessionAuthService: createSessionAuthService({ jwtService, sessionRepository: repository }),
    })
    const app = createApp({
        userSearchService: {
            async searchUsers() {
                assert.fail('Unexpected user search in auth-only tests')
            },
        },
        roleChangeService: {
            async changeUserRole() {
                assert.fail('Unexpected role mutation in auth-only tests')
            },
        },
        authorizationService: {
            async hasAnyRole() {
                assert.fail('Unexpected role check in auth-only tests')
            },
        },
        roleService: {
            async listRoles() {
                assert.fail('Unexpected role catalog lookup in auth-only tests')
            },
        },
        webOrigin: config.webOrigin, requireSession, authService, jwtService,
        sessionService, sessionRepository: repository, sessionCookie,
        loginCsrfProtection, loginCsrfCookie,
        logger: { error(...args) { stats.logs.push(args) } },
    })
    const server = app.listen(0, '127.0.0.1')
    t.after(async () => {
        if (server.listening) await new Promise((resolve, reject) => {
            server.close((error) => error ? reject(error) : resolve())
        })
    })
    await once(server, 'listening')
    const baseUrl = `http://127.0.0.1:${server.address().port}/api/v1/auth`

    async function send(path, {
        method = 'GET', cookieHeader, csrfToken, origin, body, contentType,
    } = {}) {
        const headers = {}
        if (cookieHeader != null) headers.Cookie = cookieHeader
        if (csrfToken != null) headers['X-CSRF-Token'] = csrfToken
        if (origin != null) headers.Origin = origin
        if (contentType != null) headers['Content-Type'] = contentType
        const response = await fetch(`${baseUrl}${path}`, {
            method, headers, body, signal: AbortSignal.timeout(5000),
        })
        const text = await response.text()
        return { response, body: text ? JSON.parse(text) : null }
    }
    async function challenge() {
        const result = await send('/login-csrf')
        assert.equal(result.response.status, 200)
        return {
            cookieHeader: result.response.headers.getSetCookie()[0].split(';')[0],
            csrfToken: result.body.csrfToken,
        }
    }
    async function login({ username = safeUser.username, password = PASSWORD, ...changes } = {}) {
        const pair = await challenge()
        return send('/login', {
            method: 'POST', origin: config.webOrigin, contentType: 'application/json',
            ...pair, body: JSON.stringify({ username, password }), ...changes,
        })
    }
    return { send, challenge, login, stats, jwtService, sessionCookie }
}

function assertFailure(result, status, code) {
    assert.equal(result.response.status, status)
    const id = result.response.headers.get('x-request-id')
    assert.match(id, UUID_PATTERN)
    assert.equal(result.response.headers.get('cache-control'), 'no-store')
    assert.equal(result.response.headers.get('set-cookie'), null)
    assert.deepEqual(Object.keys(result.body).sort(), ['code', 'message', 'request_id'])
    assert.equal(result.body.code, code)
    assert.equal(result.body.request_id, id)
}

function getSessionCookie(result) {
    return result.response.headers.getSetCookie()
        .find((value) => value.startsWith(`${config.cookie.name}=`)).split(';')[0]
}

test('real app supports login, current user, session CSRF and logout together', async (t) => {
    const fixture = await startFixture(t)
    const result = await fixture.login()
    assert.equal(result.response.status, 200)
    assert.deepEqual(result.body, { user: safeUser })
    const cookieHeader = getSessionCookie(result)
    const jwt = fixture.sessionCookie.readSessionToken(cookieHeader)
    const identity = await fixture.jwtService.verifySession(jwt)
    assert.equal(identity.userId, safeUser.userId)
    assert.equal(fixture.stats.rows.size, 1)
    assert.deepEqual((await fixture.send('/me', { cookieHeader })).body, { user: safeUser })
    const csrf = await fixture.send('/csrf', { cookieHeader })
    assert.equal(csrf.response.status, 200)
    const logout = await fixture.send('/logout', {
        method: 'POST', origin: config.webOrigin, cookieHeader, csrfToken: csrf.body.csrfToken,
    })
    assert.equal(logout.response.status, 204)
    assert.ok(await fixture.jwtService.verifySession(jwt))
    assertFailure(await fixture.send('/me', { cookieHeader }), 401, 'AUTH_REQUIRED')
    assert.deepEqual(fixture.stats.logs, [])
})

test('real app checks Origin before login credentials or session creation', async (t) => {
    const fixture = await startFixture(t)
    for (const origin of [null, 'https://attacker.example']) {
        assertFailure(await fixture.login({ origin }), 403, 'ORIGIN_NOT_ALLOWED')
    }
    assert.deepEqual(fixture.stats.lookups, [])
    assert.equal(fixture.stats.rows.size, 0)
})

test('real app requires matching challenge cookie and header before credentials', async (t) => {
    const fixture = await startFixture(t)
    for (const changes of [
        { cookieHeader: null }, { csrfToken: null }, { csrfToken: 'invalid' },
    ]) assertFailure(await fixture.login(changes), 403, 'CSRF_INVALID')
    const first = await fixture.challenge()
    const second = await fixture.challenge()
    assertFailure(await fixture.login({ cookieHeader: first.cookieHeader, csrfToken: second.csrfToken }),
        403, 'CSRF_INVALID')
    assert.deepEqual(fixture.stats.lookups, [])
    assert.equal(fixture.stats.rows.size, 0)
})

test('real app rejects media type, JSON, size and field errors before credential lookup', async (t) => {
    const fixture = await startFixture(t)
    for (const [changes, status, code] of [
        [{ contentType: 'text/plain' }, 415, 'UNSUPPORTED_MEDIA_TYPE'],
        [{ body: '{' }, 400, 'INVALID_JSON'],
        [{ body: 'x'.repeat(16 * 1024 + 1) }, 413, 'PAYLOAD_TOO_LARGE'],
        [{ body: '{"username":"student_demo","password":"x","role":"system_admin"}' }, 400, 'INVALID_LOGIN_INPUT'],
    ]) assertFailure(await fixture.login(changes), status, code)
    assert.deepEqual(fixture.stats.lookups, [])
    assert.equal(fixture.stats.rows.size, 0)
})

test('wrong, missing, inactive and unverified accounts get the same credential rejection', async (t) => {
    const fixture = await startFixture(t)
    const messages = []
    for (const data of [
        { password: 'wrong' }, { username: 'missing_user', password: DUMMY_PASSWORD },
        { username: 'inactive_user' }, { username: 'unverified_user' },
    ]) {
        const result = await fixture.login(data)
        assertFailure(result, 401, 'INVALID_CREDENTIALS')
        assert.equal(result.response.headers.get('www-authenticate'), 'Session realm="P32"')
        messages.push(result.body.message)
    }
    assert.equal(new Set(messages).size, 1)
    assert.equal(fixture.stats.rows.size, 0)
    assert.deepEqual(fixture.stats.logs, [])
})

test('real app enforces account quota before the next expensive password verification', async (t) => {
    const fixture = await startFixture(t)
    for (let index = 0; index < 5; index += 1) {
        assertFailure(await fixture.login({ password: 'wrong' }), 401, 'INVALID_CREDENTIALS')
    }
    const result = await fixture.login({ password: 'wrong' })
    assertFailure(result, 429, 'LOGIN_RATE_LIMITED')
    assert.ok(Number(result.response.headers.get('retry-after')) > 0)
    assert.equal(fixture.stats.lookups.length, 5)
    assert.equal(fixture.stats.rows.size, 0)
})

test('real app enforces the IP quota before challenge validation', async (t) => {
    const fixture = await startFixture(t)
    for (let index = 0; index < 60; index += 1) {
        assertFailure(await fixture.send('/login', { method: 'POST', origin: config.webOrigin }),
            403, 'CSRF_INVALID')
    }
    const result = await fixture.send('/login', { method: 'POST', origin: config.webOrigin })
    assertFailure(result, 429, 'LOGIN_RATE_LIMITED')
    assert.equal(result.response.headers.get('ratelimit-policy').includes('p32-login-account'), false)
    assert.deepEqual(fixture.stats.lookups, [])
})

test('relogin creates a fresh session and logout keeps the other session usable', async (t) => {
    const fixture = await startFixture(t)
    const first = await fixture.login({ username: ' Student_Demo ' })
    assert.equal(first.response.status, 200)
    const firstCookie = getSessionCookie(first)
    const pair = await fixture.challenge()
    const second = await fixture.login({
        cookieHeader: `${pair.cookieHeader}; ${firstCookie}`, csrfToken: pair.csrfToken,
    })
    assert.equal(second.response.status, 200)
    const secondCookie = getSessionCookie(second)
    assert.notEqual(firstCookie, secondCookie)
    assert.equal(fixture.stats.rows.size, 2)
    const csrf = await fixture.send('/csrf', { cookieHeader: firstCookie })
    assert.equal((await fixture.send('/logout', {
        method: 'POST', origin: config.webOrigin,
        cookieHeader: firstCookie, csrfToken: csrf.body.csrfToken,
    })).response.status, 204)
    assertFailure(await fixture.send('/me', { cookieHeader: firstCookie }), 401, 'AUTH_REQUIRED')
    assert.equal((await fixture.send('/me', { cookieHeader: secondCookie })).response.status, 200)
    assert.deepEqual(fixture.stats.logs, [])
})
