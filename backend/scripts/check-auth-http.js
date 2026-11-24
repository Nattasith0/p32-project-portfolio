import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { pool } from '../src/database/pool.js'
import { createApp } from '../src/app.js'
import { createAuthorizationRepository } from '../src/modules/authorization/authorization.repository.js'
import { createAuthorizationService } from '../src/modules/authorization/authorization.service.js'
import { createRoleRepository } from '../src/modules/roles/roles.repository.js'
import { createRoleService } from '../src/modules/roles/roles.service.js'
import { readAuthConfig } from '../src/config/auth.config.js'
import { createCsrfProtection } from '../src/security/csrf.js'
import { createJwtService } from '../src/security/jwt.js'
import { createSessionCookie } from '../src/modules/auth/session.cookie.js'
import { createSessionRepository } from '../src/modules/auth/session.repository.js'
import { createSessionService } from '../src/modules/auth/session.service.js'
import { createSessionAuthService } from '../src/modules/auth/session-auth.service.js'
import { createRequireSession } from '../src/modules/auth/auth.middleware.js'
import { createLoginCsrfProtection } from '../src/security/login-csrf.js'
import { createLoginCsrfCookie } from '../src/modules/auth/login-csrf.cookie.js'
import { createAuthRepository } from '../src/modules/auth/auth.repository.js'
import { createAuthService } from '../src/modules/auth/auth.service.js'
import { hashPassword } from '../src/security/password.js'

const usernames = ['student_demo', 'admin_demo']
const sessionIds = []
const logs = []
const sessionsQuery = `
    SELECT session_id, user_id, csrf_token_hash,
           created_at::text AS created_at,
           expires_at::text AS expires_at,
           revoked_at::text AS revoked_at
    FROM p32.auth_sessions
    ORDER BY session_id
`
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

const usersQuery = `
    SELECT user_id, username, display_name, is_active,
           email_verified_at::text AS email_verified_at,
           updated_at::text AS updated_at
    FROM p32.users
    WHERE username IN ($1, $2)
    ORDER BY username
`

function assertUnauthorized({ response, body }) {
    const requestId = response.headers.get('x-request-id')

    assert.equal(response.status, 401)
    assert.match(requestId, UUID_PATTERN)
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.equal(
        response.headers.get('www-authenticate'),
        'Session realm="P32"',
    )
    assert.deepEqual(body, {
        code: 'AUTH_REQUIRED',
        message: 'กรุณาเข้าสู่ระบบ',
        request_id: requestId,
    })
}

function assertRejected(result, status, code, message) {
    const requestId = result.response.headers.get('x-request-id')
    assert.equal(result.response.status, status)
    assert.match(requestId, UUID_PATTERN)
    assert.equal(result.response.headers.get('cache-control'), 'no-store')
    assert.equal(result.response.headers.get('set-cookie'), null)
    assert.deepEqual(result.body, { code, message, request_id: requestId })
}

async function closeServer(server) {
    if (!server?.listening) return

    await new Promise((resolve, reject) => {
        server.close((error) => {
            if (error) reject(error)
            else resolve()
        })
    })
}

let client
let server
let checkName = 'development target'

try {
    assert.equal(process.env.NODE_ENV, 'development')
    assert.ok(
        ['127.0.0.1', 'localhost', '::1'].includes(process.env.PGHOST)
    )

    client = await pool.connect()

    const target = await client.query(`
        SELECT current_user AS db_user,
               current_database() AS db_name,
               current_setting('is_superuser') AS is_superuser
    `)

    assert.equal(target.rows[0].db_user, 'p32_app')
    assert.equal(target.rows[0].db_name, 'p32_dev')
    assert.equal(target.rows[0].is_superuser, 'off')

    checkName = 'development login password configuration'
    const studentPassword = process.env.P32_SEED_STUDENT_PASSWORD
    assert.equal(typeof studentPassword, 'string')
    assert.ok(Array.from(studentPassword).length >= 15)
    assert.ok(Array.from(studentPassword).length <= 1024)

    checkName = 'development accounts'
    const usersBefore = await client.query(usersQuery, usernames)
    const sessionsBefore = await client.query(sessionsQuery)
    const student = usersBefore.rows.find(
        (user) => user.username === 'student_demo'
    )
    const admin = usersBefore.rows.find(
        (user) => user.username === 'admin_demo'
    )

    assert.ok(student)
    assert.ok(admin)
    assert.equal(student.is_active, true)
    assert.ok(student.email_verified_at)

    // กุญแจของ server ทดสอบ แยกจากกุญแจจริงใน .env
    const config = readAuthConfig({
        NODE_ENV: 'test',
        P32_WEB_ORIGIN: 'http://127.0.0.1',
        P32_JWT_SECRET_HEX: randomBytes(32).toString('hex'),
        P32_CSRF_SECRET_HEX: randomBytes(32).toString('hex'),
    })

    // ต้องใช้ client เดียวกับ BEGIN เพื่อให้ HTTP เห็น session ที่ยังไม่ commit
    const authRepository = createAuthRepository(client)
    const authService = createAuthService({
        findUserByUsername: authRepository.findUserByUsername,
        dummyPasswordHash: await hashPassword(randomBytes(32).toString('hex')),
    })
    const repository = createSessionRepository(client)
    const jwtService = createJwtService({ secretHex: config.jwtSecretHex })
    const sessionCookie = createSessionCookie(config.cookie)
    const loginCsrfProtection = createLoginCsrfProtection({
        secretHex: config.csrfSecretHex,
    })
    const loginCsrfCookie = createLoginCsrfCookie(config.cookie.options)
    const csrfProtection = createCsrfProtection(config.csrfSecretHex)
    const sessionService = createSessionService({
        sessionRepository: repository,
        csrfProtection,
    })
    const sessionAuthService = createSessionAuthService({
        jwtService,
        sessionRepository: repository,
    })
    const requireSession = createRequireSession({
        sessionCookie,
        sessionAuthService,
    })
    const authorizationRepository = createAuthorizationRepository(client)
    const authorizationService = createAuthorizationService({ authorizationRepository })
    const roleRepository = createRoleRepository(client)
    const roleService = createRoleService({ roleRepository })

    const app = createApp({
        userSearchService: {
            async searchUsers() {
                assert.fail('Unexpected user search in auth HTTP checks')
            },
        },
        // ตัวตรวจ auth ถือ transaction ของ sessions เอง ห้าม mutation บทบาทจาก fixture นี้
        roleChangeService: {
            async changeUserRole() {
                assert.fail('Unexpected role mutation in auth HTTP checks')
            },
        },
        authorizationService,
        roleService,
        webOrigin: config.webOrigin,
        requireSession,
        authService,
        jwtService,
        sessionService,
        sessionRepository: repository,
        sessionCookie,
        loginCsrfProtection,
        loginCsrfCookie,
        logger: {
            error(...args) {
                logs.push(args)
            },
        },
    })

    await client.query('BEGIN')

    try {
        checkName = 'session creation and HTTP startup'
        const session = await sessionService.startSession({
            userId: student.user_id,
        })
        sessionIds.push(session.sessionId)
        const token = await jwtService.signSession(session)
        const cookie = `${config.cookie.name}=${token}`

        server = app.listen(0, '127.0.0.1')
        await once(server, 'listening')
        const baseUrl =
            `http://127.0.0.1:${server.address().port}/api/v1/auth`

        async function send(path, {
            method = 'GET', cookieHeader, csrfToken, origin, body, contentType,
        } = {}) {
            const headers = {}
            if (cookieHeader != null) headers.Cookie = cookieHeader
            if (csrfToken != null) headers['X-CSRF-Token'] = csrfToken
            if (origin != null) headers.Origin = origin
            if (contentType != null) headers['Content-Type'] = contentType

            const response = await fetch(`${baseUrl}${path}`, {
                method,
                headers,
                body,
                signal: AbortSignal.timeout(5000),
            })
            const text = await response.text()
            return { response, text, body: text ? JSON.parse(text) : null }
        }

        function get(cookieHeader, path = '/me') {
            return send(path, { cookieHeader })
        }

        checkName = 'public login challenge without a session cookie'
        const loginChallenge = await get(undefined, '/login-csrf')
        assert.equal(loginChallenge.response.status, 200)
        assert.equal(loginChallenge.response.headers.get('cache-control'), 'no-store')
        assert.match(loginChallenge.response.headers.get('x-request-id'), UUID_PATTERN)
        assert.deepEqual(Object.keys(loginChallenge.body), ['csrfToken'])
        const challengeHeaders = loginChallenge.response.headers.getSetCookie()
        assert.equal(challengeHeaders.length, 1)
        assert.ok(challengeHeaders[0].startsWith('p32_login_csrf_dev='))
        const challengeCookie = loginCsrfCookie.readChallengeCookie(
            challengeHeaders[0].split(';')[0]
        )
        assert.ok(challengeCookie)
        assert.equal(loginCsrfProtection.verifyChallenge({
            cookieValue: challengeCookie,
            csrfToken: loginChallenge.body.csrfToken,
        }), true)

        checkName = 'a fresh challenge does not replace the session cookie'
        const nextChallenge = await get(cookie, '/login-csrf')
        assert.equal(nextChallenge.response.status, 200)
        const nextHeaders = nextChallenge.response.headers.getSetCookie()
        assert.equal(nextHeaders.length, 1)
        assert.ok(nextHeaders[0].startsWith('p32_login_csrf_dev='))
        const nextCookie = loginCsrfCookie.readChallengeCookie(
            nextHeaders[0].split(';')[0]
        )
        assert.ok(nextCookie)
        assert.notEqual(nextCookie, challengeCookie)
        assert.notEqual(nextChallenge.body.csrfToken, loginChallenge.body.csrfToken)
        assert.equal(loginCsrfProtection.verifyChallenge({
            cookieValue: nextCookie,
            csrfToken: nextChallenge.body.csrfToken,
        }), true)
        assert.equal(loginCsrfProtection.verifyChallenge({
            cookieValue: nextCookie,
            csrfToken: loginChallenge.body.csrfToken,
        }), false)

        checkName = 'active session returns safe user fields'
        const valid = await get(cookie)
        assert.equal(valid.response.status, 200)
        assert.match(valid.response.headers.get('x-request-id'), UUID_PATTERN)
        assert.equal(valid.response.headers.get('cache-control'), 'no-store')
        assert.equal(valid.response.headers.get('x-powered-by'), null)
        assert.deepEqual(valid.body, {
            user: {
                userId: student.user_id,
                username: student.username,
                displayName: student.display_name,
            },
        })

        checkName = 'CSRF token matches the stored session digest'
        const csrf = await get(cookie, '/csrf')
        assert.equal(csrf.response.status, 200)
        assert.equal(csrf.response.headers.get('cache-control'), 'no-store')
        assert.match(csrf.response.headers.get('x-request-id'), UUID_PATTERN)
        assert.deepEqual(Object.keys(csrf.body), ['csrfToken'])

        const active = await repository.findActiveSession({
            sessionId: session.sessionId,
            userId: student.user_id,
        })
        assert.ok(active)
        assert.equal(csrfProtection.verifyToken(csrf.body.csrfToken, {
            sessionId: session.sessionId,
            userId: student.user_id,
            csrfTokenHash: active.csrf_token_hash,
        }), true)

        checkName = 'CSRF token remains the same for the active session'
        const repeated = await get(cookie, '/csrf')
        assert.equal(repeated.response.status, 200)
        assert.deepEqual(repeated.body, csrf.body)

        checkName = 'CSRF endpoint without a session cookie'
        assertUnauthorized(await get(undefined, '/csrf'))

        checkName = 'missing cookie'
        assertUnauthorized(await get())

        checkName = 'malformed cookie'
        assertUnauthorized(await get(`${config.cookie.name}=not-a-jwt`))

        checkName = 'wrong session owner'
        const wrongOwnerToken = await jwtService.signSession({
            ...session,
            userId: admin.user_id,
        })
        assert.ok(await jwtService.verifySession(wrongOwnerToken))
        assertUnauthorized(await get(
            `${config.cookie.name}=${wrongOwnerToken}`
        ))
        assertUnauthorized(await get(
            `${config.cookie.name}=${wrongOwnerToken}`,
            '/csrf',
        ))

        checkName = 'second session remains independent'
        const secondSession = await sessionService.startSession({
            userId: student.user_id,
        })
        sessionIds.push(secondSession.sessionId)
        const secondToken = await jwtService.signSession(secondSession)
        const secondCookie = `${config.cookie.name}=${secondToken}`
        const secondCsrf = await get(secondCookie, '/csrf')
        assert.equal(secondCsrf.response.status, 200)
        assert.notEqual(secondCsrf.body.csrfToken, csrf.body.csrfToken)

        async function readSessionState() {
            const result = await client.query(
                `SELECT session_id, user_id, csrf_token_hash,
                        created_at::text AS created_at,
                        expires_at::text AS expires_at,
                        revoked_at::text AS revoked_at
                 FROM p32.auth_sessions
                 WHERE session_id = ANY($1::uuid[])
                 ORDER BY session_id`,
                [sessionIds],
            )
            return result.rows
        }

        const stateBeforeLogout = await readSessionState()
        assert.equal(stateBeforeLogout.length, 2)

        const logoutDefaults = {
            method: 'POST',
            cookieHeader: cookie,
            csrfToken: csrf.body.csrfToken,
            origin: config.webOrigin,
        }
        const rejectedRequests = [
            {
                name: 'logout without Origin',
                changes: { origin: null },
                status: 403,
                code: 'ORIGIN_NOT_ALLOWED',
                message: 'ไม่อนุญาตคำขอจากแหล่งที่มานี้',
            },
            {
                name: 'logout from an untrusted Origin',
                changes: { origin: 'https://attacker.example' },
                status: 403,
                code: 'ORIGIN_NOT_ALLOWED',
                message: 'ไม่อนุญาตคำขอจากแหล่งที่มานี้',
            },
            {
                name: 'logout without a session cookie',
                changes: { cookieHeader: null },
                status: 401,
                code: 'AUTH_REQUIRED',
                message: 'กรุณาเข้าสู่ระบบ',
            },
            {
                name: 'logout without a CSRF header',
                changes: { csrfToken: null },
                status: 403,
                code: 'CSRF_INVALID',
                message: 'ไม่สามารถยืนยันคำขอได้',
            },
            {
                name: 'logout with a malformed CSRF token',
                changes: { csrfToken: 'invalid-token' },
                status: 403,
                code: 'CSRF_INVALID',
                message: 'ไม่สามารถยืนยันคำขอได้',
            },
            {
                name: 'logout with another session CSRF token',
                changes: { csrfToken: secondCsrf.body.csrfToken },
                status: 403,
                code: 'CSRF_INVALID',
                message: 'ไม่สามารถยืนยันคำขอได้',
            },
        ]

        for (const rejected of rejectedRequests) {
            checkName = rejected.name
            const result = await send('/logout', {
                ...logoutDefaults,
                ...rejected.changes,
            })
            assertRejected(result, rejected.status, rejected.code, rejected.message)
            // การถูกปฏิเสธต้องไม่เปลี่ยนข้อมูล session หรือส่ง cookie มาล้าง
            assert.deepEqual(await readSessionState(), stateBeforeLogout)
        }

        checkName = 'protected logout revokes only the current session'
        const loggedOut = await send('/logout', logoutDefaults)
        assert.equal(loggedOut.response.status, 204)
        assert.equal(loggedOut.text, '')
        assert.equal(loggedOut.response.headers.get('cache-control'), 'no-store')
        assert.match(loggedOut.response.headers.get('x-request-id'), UUID_PATTERN)

        const clearedCookie = loggedOut.response.headers.get('set-cookie')
        assert.ok(clearedCookie.startsWith(`${config.cookie.name}=;`))
        assert.match(clearedCookie, /; Path=\/(?:;|$)/)
        assert.match(clearedCookie, /; HttpOnly(?:;|$)/)
        assert.match(clearedCookie, /; SameSite=Lax(?:;|$)/)
        assert.doesNotMatch(clearedCookie, /; (?:Domain|Max-Age)=/i)
        assert.doesNotMatch(clearedCookie, /; Secure(?:;|$)/)
        const expiration = /; Expires=([^;]+)/i.exec(clearedCookie)
        assert.ok(expiration)
        assert.equal(Date.parse(expiration[1]), 0)

        const stateAfterLogout = await readSessionState()
        const revoked = stateAfterLogout.find(
            (row) => row.session_id === session.sessionId
        )
        assert.ok(revoked.revoked_at)
        assert.deepEqual(
            stateAfterLogout.find((row) => row.session_id === secondSession.sessionId),
            stateBeforeLogout.find((row) => row.session_id === secondSession.sessionId),
        )

        // ส่ง JWT เดิมกลับไปด้วยตนเอง แม้ cookie ถูกล้างแล้ว ต้องใช้ต่อไม่ได้
        assert.ok(await jwtService.verifySession(token))
        assertUnauthorized(await get(cookie))
        checkName = 'CSRF endpoint after session revocation'
        assertUnauthorized(await get(cookie, '/csrf'))

        checkName = 'repeated logout with the revoked session is rejected'
        const repeatedLogout = await send('/logout', logoutDefaults)
        assertUnauthorized(repeatedLogout)
        assert.equal(repeatedLogout.response.headers.get('set-cookie'), null)

        checkName = 'another session still works after logout'
        assert.equal((await get(secondCookie)).response.status, 200)
        const remainingCsrf = await get(secondCookie, '/csrf')
        assert.equal(remainingCsrf.response.status, 200)
        assert.deepEqual(remainingCsrf.body, secondCsrf.body)
        // ตรวจ HTTP login จริงภายใน transaction เดิม หลัง checks ของ session A/B
        checkName = 'HTTP login challenge'
        async function requestLoginChallenge() {
            const result = await get(undefined, '/login-csrf')
            assert.equal(result.response.status, 200)
            assert.deepEqual(Object.keys(result.body), ['csrfToken'])
            const challengeHeaders = result.response.headers.getSetCookie()
            assert.equal(challengeHeaders.length, 1)
            const challengeCookie = challengeHeaders[0].split(';')[0]
            assert.ok(loginCsrfCookie.readChallengeCookie(challengeCookie))
            return { cookieHeader: challengeCookie, csrfToken: result.body.csrfToken }
        }
        const challenge = await requestLoginChallenge()
        const loginDefaults = {
            method: 'POST', origin: config.webOrigin,
            contentType: 'application/json',
            body: JSON.stringify({ username: 'student_demo', password: studentPassword }),
            ...challenge,
        }
        const sessionStateBeforeLogin = (await client.query(sessionsQuery)).rows
        const loginDenials = [
            { changes: { origin: null }, status: 403, code: 'ORIGIN_NOT_ALLOWED', message: 'ไม่อนุญาตคำขอจากแหล่งที่มานี้' },
            { changes: { origin: 'https://attacker.example' }, status: 403, code: 'ORIGIN_NOT_ALLOWED', message: 'ไม่อนุญาตคำขอจากแหล่งที่มานี้' },
            { changes: { cookieHeader: null }, status: 403, code: 'CSRF_INVALID', message: 'ไม่สามารถยืนยันคำขอได้' },
            { changes: { csrfToken: null }, status: 403, code: 'CSRF_INVALID', message: 'ไม่สามารถยืนยันคำขอได้' },
            { changes: { csrfToken: 'invalid' }, status: 403, code: 'CSRF_INVALID', message: 'ไม่สามารถยืนยันคำขอได้' },
            { changes: { contentType: 'text/plain' }, status: 415, code: 'UNSUPPORTED_MEDIA_TYPE', message: 'รูปแบบข้อมูลคำขอไม่รองรับ' },
            { changes: { body: '{' }, status: 400, code: 'INVALID_JSON', message: 'รูปแบบ JSON ไม่ถูกต้อง' },
            { changes: { body: 'x'.repeat(16 * 1024 + 1) }, status: 413, code: 'PAYLOAD_TOO_LARGE', message: 'ข้อมูลคำขอมีขนาดเกินกำหนด' },
            { changes: { body: '{}' }, status: 400, code: 'INVALID_LOGIN_INPUT', message: 'ข้อมูลเข้าสู่ระบบไม่ถูกต้อง' },
        ]
        for (const denied of loginDenials) {
            checkName = `HTTP login rejection ${denied.code}`
            const result = await send('/login', { ...loginDefaults, ...denied.changes })
            assertRejected(result, denied.status, denied.code, denied.message)
            assert.deepEqual((await client.query(sessionsQuery)).rows, sessionStateBeforeLogin)
        }

        const wrongCharacters = Array.from(studentPassword)
        wrongCharacters[0] = wrongCharacters[0] === 'x' ? 'y' : 'x'
        const wrongBody = JSON.stringify({ username: 'student_demo', password: wrongCharacters.join('') })
        function assertCredentialsRejected(result) {
            assertRejected(result, 401, 'INVALID_CREDENTIALS', 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง')
            assert.equal(result.response.headers.get('www-authenticate'), 'Session realm="P32"')
        }

        checkName = 'HTTP login wrong password'
        assertCredentialsRejected(await send('/login', { ...loginDefaults, body: wrongBody }))
        checkName = 'HTTP login missing account'
        const missingUsername = `p32_missing_http_${randomBytes(8).toString('hex')}`
        assert.equal(await authRepository.findUserByUsername(missingUsername), null)
        assertCredentialsRejected(await send('/login', {
            ...loginDefaults, body: JSON.stringify({ username: missingUsername, password: studentPassword }),
        }))

        checkName = 'HTTP login disabled account'
        await client.query('SAVEPOINT login_disabled_account')
        try {
            await client.query('UPDATE p32.users SET is_active = FALSE WHERE user_id = $1', [student.user_id])
            assertCredentialsRejected(await send('/login', loginDefaults))
        } finally {
            await client.query('ROLLBACK TO SAVEPOINT login_disabled_account')
            await client.query('RELEASE SAVEPOINT login_disabled_account')
        }
        assert.deepEqual((await client.query(sessionsQuery)).rows, sessionStateBeforeLogin)

        async function loginAndReadSession(pair) {
            const result = await send('/login', {
                ...loginDefaults, ...pair,
                body: JSON.stringify({ username: ' Student_Demo ', password: studentPassword }),
            })
            assert.equal(result.response.status, 200)
            assert.equal(result.response.headers.get('cache-control'), 'no-store')
            assert.deepEqual(result.body, { user: {
                userId: student.user_id, username: student.username, displayName: student.display_name,
            } })
            const headers = result.response.headers.getSetCookie()
            assert.equal(headers.length, 2)
            const header = headers.find((value) => value.startsWith(`${config.cookie.name}=`))
            const clearedChallenge = headers.find((value) => value.startsWith('p32_login_csrf_dev=;'))
            assert.ok(header)
            assert.ok(clearedChallenge)
            assert.equal(Date.parse(/; Expires=([^;]+)/.exec(clearedChallenge)[1]), 0)
            assert.match(header, /; HttpOnly(?:;|$)/)
            assert.match(header, /; SameSite=Lax(?:;|$)/)
            assert.doesNotMatch(header, /; Domain=/i)
            const cookieHeader = header.split(';')[0]
            const jwt = sessionCookie.readSessionToken(cookieHeader)
            const identity = await jwtService.verifySession(jwt)
            assert.ok(identity)
            sessionIds.push(identity.sessionId)
            assert.equal(identity.userId, student.user_id)
            const active = await repository.findActiveSession(identity)
            assert.ok(active)
            assert.equal(active.expires_at.getTime(), identity.expiresAt.getTime())
            return { cookieHeader, jwt, identity }
        }

        checkName = 'HTTP login then current user and CSRF'
        const firstLogin = await loginAndReadSession(challenge)
        assert.equal((await get(firstLogin.cookieHeader)).response.status, 200)
        const firstLoginCsrf = await get(firstLogin.cookieHeader, '/csrf')
        assert.equal(firstLoginCsrf.response.status, 200)
        checkName = 'HTTP login session logout'
        const firstLogout = await send('/logout', {
            method: 'POST', origin: config.webOrigin,
            cookieHeader: firstLogin.cookieHeader, csrfToken: firstLoginCsrf.body.csrfToken,
        })
        assert.equal(firstLogout.response.status, 204)
        assert.ok(await jwtService.verifySession(firstLogin.jwt))
        assertUnauthorized(await get(firstLogin.cookieHeader))

        checkName = 'HTTP login creates another fresh session'
        const secondLogin = await loginAndReadSession(await requestLoginChallenge())
        assert.notEqual(firstLogin.identity.sessionId, secondLogin.identity.sessionId)
        assert.equal((await get(secondLogin.cookieHeader)).response.status, 200)
        assertUnauthorized(await get(firstLogin.cookieHeader))

        checkName = 'HTTP login per-account quota'
        // student_demo: wrong/disabled/first login/second login = 4 validated attempts
        const stateBeforeRateChecks = (await client.query(sessionsQuery)).rows
        assertCredentialsRejected(await send('/login', { ...loginDefaults, body: wrongBody }))
        const accountLimited = await send('/login', loginDefaults)
        assertRejected(accountLimited, 429, 'LOGIN_RATE_LIMITED',
            'มีคำขอเข้าสู่ระบบมากเกินไป กรุณาลองใหม่ภายหลัง')
        assert.ok(Number(accountLimited.response.headers.get('retry-after')) > 0)
        assert.ok(accountLimited.response.headers.get('ratelimit-policy').includes('p32-login-account'))
        assert.deepEqual((await client.query(sessionsQuery)).rows, stateBeforeRateChecks)

        checkName = 'HTTP login per-IP quota before credentials'
        let ipLimited = false
        for (let index = 0; index < 61; index += 1) {
            const result = await send('/login', { ...loginDefaults, csrfToken: 'invalid' })
            if (result.response.status === 429) {
                assertRejected(result, 429, 'LOGIN_RATE_LIMITED',
                    'มีคำขอเข้าสู่ระบบมากเกินไป กรุณาลองใหม่ภายหลัง')
                assert.ok(Number(result.response.headers.get('retry-after')) > 0)
                assert.equal(result.response.headers.get('ratelimit-policy').includes('p32-login-account'), false)
                ipLimited = true
                break
            }
            assertRejected(result, 403, 'CSRF_INVALID', 'ไม่สามารถยืนยันคำขอได้')
        }
        assert.equal(ipLimited, true)
        assert.deepEqual((await client.query(sessionsQuery)).rows, stateBeforeRateChecks)
        assert.deepEqual(logs, [])
    } finally {
        // หยุดรับ HTTP ก่อนคืนข้อมูลใน transaction
        try {
            await closeServer(server)
        } finally {
            await client.query('ROLLBACK')
        }
    }

    checkName = 'rollback cleanup'
    const remaining = await client.query(
        `SELECT session_id FROM p32.auth_sessions
         WHERE session_id = ANY($1::uuid[])`,
        [sessionIds],
    )
    assert.equal(remaining.rowCount, 0)
    const sessionsAfter = await client.query(sessionsQuery)
    assert.deepEqual(sessionsAfter.rows, sessionsBefore.rows)

    const usersAfter = await client.query(usersQuery, usernames)
    assert.deepEqual(usersAfter.rows, usersBefore.rows)

    console.log('Auth HTTP/database checks passed (/login-csrf, /login, /me, /csrf and /logout); test data rolled back.')
} catch (error) {
    // ไม่แสดง error object เพราะอาจมีข้อมูลจากคำขอหรือฐานข้อมูล
    console.error(
        `Auth HTTP/database checks failed (${checkName}):`,
        error.code ?? error.name,
    )
    process.exitCode = 1
} finally {
    if (client) client.release(true)
    await pool.end()
}
