import test from 'node:test'
import assert from 'node:assert/strict'
import { SignJWT, jwtVerify } from 'jose'
import { createJwtService } from '../src/security/jwt.js'

// กุญแจสมมติสำหรับ tests เท่านั้น ห้ามใช้ในระบบจริง
const secretHex = '33'.repeat(32)
const key = Buffer.from(secretHex, 'hex')

const fixedTime = Date.parse('2026-11-02T03:00:00.987Z')
const issuedAt = Math.floor(fixedTime / 1000)

const session = {
    sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    expiresAt: new Date((issuedAt + 1800) * 1000),
}

const claims = {
    iss: 'p32-api',
    aud: 'p32-web',
    sub: session.userId,
    jti: session.sessionId,
    iat: issuedAt,
    exp: issuedAt + 1800,
}

function makeService(now = () => fixedTime) {
    return createJwtService({ secretHex, now })
}

// สร้าง token ทดสอบโดยตรง เพื่อทดสอบข้อมูลที่ helper ไม่ยอมสร้าง
async function rawToken(payload, {
    alg = 'HS256',
    typ = 'JWT',
    signingKey = key,
} = {}) {
    return new SignJWT(payload)
        .setProtectedHeader({ alg, typ })
        .sign(signingKey)
}

test('signs expected claims and returns only session fields', async () => {
    const service = makeService()
    const token = await service.signSession(session)

    const verified = await jwtVerify(token, key, {
        algorithms: ['HS256'],
        issuer: 'p32-api',
        audience: 'p32-web',
        typ: 'JWT',
        currentDate: new Date(fixedTime),
    })

    assert.deepEqual(verified.protectedHeader, {
        alg: 'HS256',
        typ: 'JWT',
    })
    assert.deepEqual(verified.payload, claims)
    assert.deepEqual(await service.verifySession(token), session)
})

test('normalizes UUIDs when signing and verifying', async () => {
    const service = makeService()

    const token = await service.signSession({
        ...session,
        sessionId: session.sessionId.toUpperCase(),
        userId: session.userId.toUpperCase(),
    })

    assert.deepEqual(await service.verifySession(token), session)

    const uppercaseToken = await rawToken({
        ...claims,
        sub: claims.sub.toUpperCase(),
        jti: claims.jti.toUpperCase(),
    })

    assert.deepEqual(
        await service.verifySession(uppercaseToken),
        session
    )
})

test('accepts before expiry and rejects at or after expiry', async () => {
    let currentTime = fixedTime
    const service = makeService(() => currentTime)
    const token = await service.signSession(session)

    currentTime = session.expiresAt.getTime() - 1
    assert.deepEqual(await service.verifySession(token), session)

    currentTime = session.expiresAt.getTime()
    assert.equal(await service.verifySession(token), null)

    currentTime += 1000
    assert.equal(await service.verifySession(token), null)
})

test('rejects tampered tokens and a different signing key', async () => {
    const service = makeService()
    const token = await service.signSession(session)

    const parts = token.split('.')
    parts[1] = Buffer.from(JSON.stringify({
        ...claims,
        sub: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    })).toString('base64url')

    assert.equal(
        await service.verifySession(parts.join('.')),
        null
    )

    const otherService = createJwtService({
        secretHex: '44'.repeat(32),
        now: () => fixedTime,
    })

    assert.equal(await otherService.verifySession(token), null)
})

test('rejects incorrect issuer, audience, type and algorithm', async () => {
    const service = makeService()

    const tokens = [
        await rawToken({ ...claims, iss: 'another-api' }),
        await rawToken({ ...claims, aud: 'another-web' }),
        await rawToken(claims, { typ: 'OTHER-TOKEN' }),
        await rawToken(claims, {
            alg: 'HS384',
            signingKey: Buffer.alloc(48, 0x55),
        }),
    ]

    for (const token of tokens) {
        assert.equal(await service.verifySession(token), null)
    }
})

test('rejects missing required claims', async () => {
    const service = makeService()

    for (const name of ['iss', 'aud', 'sub', 'jti', 'iat', 'exp']) {
        const incomplete = { ...claims }
        delete incomplete[name]

        const token = await rawToken(incomplete)
        assert.equal(await service.verifySession(token), null)
    }
})

test('rejects invalid identifiers, times and excessive lifetime', async () => {
    const service = makeService()

    const invalidClaims = [
        { sub: 'student_demo' },
        { jti: 'not-a-session' },
        { iat: 'invalid' },
        { exp: 'invalid' },
        { iat: issuedAt + 1 },
        { iat: issuedAt + 0.5 },
        { iat: -1 },
        { exp: claims.exp + 0.5 },
        { exp: issuedAt },
        { exp: issuedAt + 1801 },
        { exp: Number.MAX_SAFE_INTEGER },
        { nbf: issuedAt + 1 },
    ]

    for (const invalid of invalidClaims) {
        const token = await rawToken({ ...claims, ...invalid })
        assert.equal(await service.verifySession(token), null)
    }
})

test('rejects malformed, oversized and unsigned tokens', async () => {
    const service = makeService()

    const header = Buffer.from(JSON.stringify({
        alg: 'none',
        typ: 'JWT',
    })).toString('base64url')

    const payload = Buffer.from(
        JSON.stringify(claims)
    ).toString('base64url')

    const invalidTokens = [
        undefined,
        null,
        123,
        {},
        '',
        'not-a-jwt',
        'a.b.c',
        '   ',
        'a'.repeat(4097),
        `${header}.${payload}.`,
    ]

    for (const token of invalidTokens) {
        assert.equal(await service.verifySession(token), null)
    }
})

test('rejects invalid identifiers when signing', async () => {
    const service = makeService()

    for (const invalid of [undefined, null, 123, '', 'student_demo']) {
        await assert.rejects(
            service.signSession({ ...session, userId: invalid }),
            TypeError
        )
        await assert.rejects(
            service.signSession({ ...session, sessionId: invalid }),
            TypeError
        )
    }
})

test('enforces expiration format and signing lifetime boundaries', async () => {
    const service = makeService()

    const invalidDates = [
        undefined,
        null,
        '2026-11-02',
        new Date(NaN),
        new Date(session.expiresAt.getTime() + 1),
    ]

    for (const expiresAt of invalidDates) {
        await assert.rejects(
            service.signSession({ ...session, expiresAt }),
            TypeError
        )
    }

    for (const seconds of [issuedAt - 1, issuedAt, issuedAt + 1801]) {
        await assert.rejects(
            service.signSession({
                ...session,
                expiresAt: new Date(seconds * 1000),
            }),
            RangeError
        )
    }

    const shortSession = {
        ...session,
        expiresAt: new Date((issuedAt + 1) * 1000),
    }

    const token = await service.signSession(shortSession)
    assert.deepEqual(await service.verifySession(token), shortSession)
})

test('rejects invalid secrets and clock dependencies', () => {
    const invalidSecrets = [
        undefined,
        null,
        123,
        '',
        '33'.repeat(31),
        '33'.repeat(33),
        'zz'.repeat(32),
        'AB'.repeat(32),
    ]

    for (const invalid of invalidSecrets) {
        assert.throws(
            () => createJwtService({ secretHex: invalid }),
            TypeError
        )
    }

    for (const now of [null, 123, 'clock']) {
        assert.throws(
            () => createJwtService({ secretHex, now }),
            TypeError
        )
    }
})

test('propagates clock failures and rejects invalid clock values', async () => {
    const token = await rawToken(claims)
    const clockError = new Error('Simulated clock failure')

    const service = makeService(() => {
        throw clockError
    })

    await assert.rejects(
        service.signSession(session),
        (error) => error === clockError
    )
    await assert.rejects(
        service.verifySession(token),
        (error) => error === clockError
    )

    for (const invalid of [
        NaN, Infinity, -1, 1.5, '0', Number.MAX_SAFE_INTEGER,
    ]) {
        const invalidClockService = makeService(() => invalid)

        await assert.rejects(
            invalidClockService.signSession(session),
            TypeError
        )
        await assert.rejects(
            invalidClockService.verifySession(token),
            TypeError
        )
    }
})