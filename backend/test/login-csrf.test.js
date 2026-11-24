import test from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { createLoginCsrfProtection } from '../src/security/login-csrf.js'
import { createCsrfProtection } from '../src/security/csrf.js'

// กุญแจและค่าทั้งหมดเป็นข้อมูลสมมติสำหรับ tests เท่านั้น
const SECRET = '11'.repeat(32)
const FIXED_TIME = Date.parse('2026-11-03T03:00:00.987Z')
const EXPIRES_SECONDS = 1793675400
const knownChallenge = Object.freeze({
    cookieValue: 'A'.repeat(43),
    csrfToken: '1793675400.EtJ0sr8pWRVL7ZoReiuAM8A9zJkAR0LDSmAgIZAxwgY',
})

function createFixture(now = () => FIXED_TIME) {
    return createLoginCsrfProtection({ secretHex: SECRET, now })
}

test('creates a limited challenge with a ten-minute whole-second expiration', () => {
    const protection = createFixture()
    const challenge = protection.createChallenge()

    assert.deepEqual(Object.keys(challenge).sort(), [
        'cookieValue', 'csrfToken', 'expiresAt',
    ])
    assert.equal(challenge.cookieValue.length, 43)
    assert.match(challenge.cookieValue, /^[A-Za-z0-9_-]{43}$/)
    assert.match(challenge.csrfToken, /^[1-9][0-9]*\.[A-Za-z0-9_-]{43}$/)
    assert.equal(challenge.expiresAt.getTime(), EXPIRES_SECONDS * 1000)
    assert.equal(challenge.expiresAt.getTime() % 1000, 0)
    assert.equal(protection.verifyChallenge(challenge), true)
})

test('creates independent challenges and rejects cookie-token pairs from different challenges', () => {
    const protection = createFixture()
    const first = protection.createChallenge()
    const second = protection.createChallenge()

    assert.notEqual(first.cookieValue, second.cookieValue)
    assert.notEqual(first.csrfToken, second.csrfToken)
    assert.equal(protection.verifyChallenge({
        cookieValue: first.cookieValue,
        csrfToken: second.csrfToken,
    }), false)
    assert.equal(protection.verifyChallenge({
        cookieValue: second.cookieValue,
        csrfToken: first.csrfToken,
    }), false)
    assert.equal(protection.verifyChallenge(first), true)
    assert.equal(protection.verifyChallenge(second), true)
})

test('accepts the independently calculated HMAC protocol vector without changing its input', () => {
    const protection = createFixture()
    const before = { ...knownChallenge }

    assert.equal(protection.verifyChallenge(knownChallenge), true)
    assert.deepEqual(knownChallenge, before)
})

test('rejects another key, another HMAC purpose and an authenticated-session CSRF token', () => {
    const protection = createFixture()
    const otherKey = createLoginCsrfProtection({
        secretHex: '22'.repeat(32),
        now: () => FIXED_TIME,
    })
    assert.equal(otherKey.verifyChallenge(knownChallenge), false)

    const otherPurposeSignature = createHmac('sha256', Buffer.from(SECRET, 'hex'))
        .update(JSON.stringify([
            'P32-CSRF-v1', knownChallenge.cookieValue, EXPIRES_SECONDS,
        ]))
        .digest('base64url')
    assert.equal(protection.verifyChallenge({
        ...knownChallenge,
        csrfToken: `${EXPIRES_SECONDS}.${otherPurposeSignature}`,
    }), false)

    const sessionToken = createCsrfProtection(SECRET).createToken({
        sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    })
    assert.equal(protection.verifyChallenge({
        ...knownChallenge,
        csrfToken: sessionToken,
    }), false)
})

test('rejects a changed cookie, expiration or signature', () => {
    const protection = createFixture()
    const [expiration, signature] = knownChallenge.csrfToken.split('.')
    const modifiedSignature =
        (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1)

    const modified = [
        { ...knownChallenge, cookieValue: 'B'.repeat(43) },
        { ...knownChallenge, csrfToken: `${Number(expiration) - 1}.${signature}` },
        { ...knownChallenge, csrfToken: `${Number(expiration) + 1}.${signature}` },
        { ...knownChallenge, csrfToken: `${expiration}.${modifiedSignature}` },
    ]
    for (const challenge of modified) {
        assert.equal(protection.verifyChallenge(challenge), false)
    }
})

test('accepts one millisecond before expiry and rejects at or after expiry', () => {
    let currentTime = EXPIRES_SECONDS * 1000 - 1
    const protection = createFixture(() => currentTime)

    assert.equal(protection.verifyChallenge(knownChallenge), true)
    currentTime += 1
    assert.equal(protection.verifyChallenge(knownChallenge), false)
    currentTime += 1
    assert.equal(protection.verifyChallenge(knownChallenge), false)
})

test('rejects a correctly signed challenge whose remaining lifetime exceeds ten minutes', () => {
    const futureIssuer = createFixture(() => FIXED_TIME + 1000)
    const futureChallenge = futureIssuer.createChallenge()

    assert.equal(futureIssuer.verifyChallenge(futureChallenge), true)
    assert.equal(createFixture().verifyChallenge(futureChallenge), false)

    // หาก clock ถอยหลังจน token เหลืออายุเกินนโยบาย ต้องไม่อนุญาต
    const clockMovedBack = createFixture(() => FIXED_TIME - 1000)
    assert.equal(clockMovedBack.verifyChallenge(knownChallenge), false)
})

test('rejects missing fields and challenge records that are not objects', () => {
    const protection = createFixture()
    for (const challenge of [
        undefined, null, '', 123, true, [], {},
        { cookieValue: knownChallenge.cookieValue },
        { csrfToken: knownChallenge.csrfToken },
    ]) {
        assert.equal(protection.verifyChallenge(challenge), false)
    }
})

test('rejects malformed nonces, oversized tokens and non-canonical expiration text', () => {
    const protection = createFixture()
    for (const cookieValue of [
        null, 123, [], '', 'a'.repeat(42), 'a'.repeat(44),
        '!'.repeat(43), 'ก'.repeat(43), `${knownChallenge.cookieValue}\n`,
    ]) {
        assert.equal(protection.verifyChallenge({
            ...knownChallenge, cookieValue,
        }), false)
    }

    const signature = knownChallenge.csrfToken.split('.')[1]
    const invalidTokens = [
        null, 123, [], '', 'x'.repeat(65),
        knownChallenge.csrfToken + '.', knownChallenge.csrfToken + '\n',
        `${EXPIRES_SECONDS}.${'a'.repeat(42)}`,
        `${EXPIRES_SECONDS}.${'a'.repeat(44)}`,
        `${EXPIRES_SECONDS}.${'!'.repeat(43)}`,
    ]
    for (const expiration of [
        '', '0', '-1', `0${EXPIRES_SECONDS}`, `+${EXPIRES_SECONDS}`,
        ` ${EXPIRES_SECONDS}`, `${EXPIRES_SECONDS}\n`,
        `${EXPIRES_SECONDS}.5`, '1e10', 'Infinity', '9007199254740992',
        '8640000000001',
    ]) {
        invalidTokens.push(`${expiration}.${signature}`)
    }
    for (const csrfToken of invalidTokens) {
        assert.equal(protection.verifyChallenge({
            ...knownChallenge, csrfToken,
        }), false)
    }
})

test('rejects malformed secrets and non-function clock dependencies', () => {
    for (const secretHex of [
        undefined, null, 123, '', 'a'.repeat(63), 'a'.repeat(65),
        'AB'.repeat(32), 'g'.repeat(64), `${SECRET}\n`,
    ]) {
        assert.throws(() => createLoginCsrfProtection({ secretHex }), TypeError)
    }
    for (const now of [null, 123, {}, 'clock']) {
        assert.throws(() => createLoginCsrfProtection({ secretHex: SECRET, now }), TypeError)
    }
})

test('propagates clock failures and rejects invalid clock values', () => {
    const failure = new Error('TEST_ONLY_CLOCK_FAILURE')
    const broken = createFixture(() => { throw failure })
    assert.throws(() => broken.createChallenge(), (error) => error === failure)
    assert.throws(() => broken.verifyChallenge(knownChallenge), (error) => error === failure)

    for (const value of [
        undefined, null, '0', NaN, Infinity, -1, 0.5,
        Number.MAX_SAFE_INTEGER + 1, 8640000000000001,
    ]) {
        const protection = createFixture(() => value)
        assert.throws(() => protection.createChallenge(), TypeError)
        assert.throws(() => protection.verifyChallenge(knownChallenge), TypeError)
    }
})

test('supports valid date boundaries and rejects expiry beyond the supported date range', () => {
    const epoch = createFixture(() => 0)
    const first = epoch.createChallenge()
    assert.equal(first.expiresAt.getTime(), 600000)
    assert.equal(epoch.verifyChallenge(first), true)

    const maxDate = 8640000000000000
    let currentTime = maxDate - 600000
    const upperBoundary = createFixture(() => currentTime)
    const last = upperBoundary.createChallenge()
    assert.equal(last.expiresAt.getTime(), maxDate)
    assert.equal(upperBoundary.verifyChallenge(last), true)
    currentTime = maxDate - 1
    assert.equal(upperBoundary.verifyChallenge(last), true)
    currentTime = maxDate
    assert.equal(upperBoundary.verifyChallenge(last), false)
    assert.throws(() => upperBoundary.createChallenge(), TypeError)
})
