import test from 'node:test'
import assert from 'node:assert/strict'
import { createCsrfProtection } from '../src/security/csrf.js'

// กุญแจและ UUID สมมติสำหรับ tests เท่านั้น ห้ามใช้เป็นกุญแจจริง
const testSecret = '11'.repeat(32)

const context = {
    sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
}

const otherSessionId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
const otherUserId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'

const protection = createCsrfProtection(testSecret)
const token = protection.createToken(context)

const session = {
    ...context,
    csrfTokenHash: protection.hashToken(token),
}

test('generates the expected token and stored digest', () => {
    assert.equal(
        token,
        '0tKaD-2Na-hv3jlRdHwQsFLSnf1QhCnlylHRXPpF560'
    )

    assert.equal(
        session.csrfTokenHash,
        '249e9d684979107bb20a0c2d7b5b11b798243b8f9f6e6648e717a90ba7cd920f'
    )
})

test('recreates the token for the same canonical context', () => {
    assert.equal(protection.createToken(context), token)

    assert.equal(protection.createToken({
        sessionId: context.sessionId.toUpperCase(),
        userId: context.userId.toUpperCase(),
    }), token)
})

test('token changes with the session, account or server key', () => {
    assert.notEqual(protection.createToken({
        ...context,
        sessionId: otherSessionId,
    }), token)

    assert.notEqual(protection.createToken({
        ...context,
        userId: otherUserId,
    }), token)

    const otherProtection = createCsrfProtection('22'.repeat(32))
    assert.notEqual(otherProtection.createToken(context), token)
})

test('verification requires the token, context, key and digest to match', () => {
    assert.equal(protection.verifyToken(token, session), true)
    assert.equal(protection.verifyToken('x'.repeat(43), session), false)

    assert.equal(protection.verifyToken(token, {
        ...session,
        sessionId: otherSessionId,
    }), false)

    assert.equal(protection.verifyToken(token, {
        ...session,
        userId: otherUserId,
    }), false)

    assert.equal(protection.verifyToken(token, {
        ...session,
        csrfTokenHash: '0'.repeat(64),
    }), false)

    const otherProtection = createCsrfProtection('22'.repeat(32))
    assert.equal(otherProtection.verifyToken(token, session), false)
})

test('rejects malformed tokens, hashes and session records', () => {
    const invalidTokens = [
        undefined, null, 123, {}, '',
        'a'.repeat(42), 'a'.repeat(44), '!'.repeat(43),
    ]

    for (const invalid of invalidTokens) {
        assert.throws(() => protection.hashToken(invalid), TypeError)
        assert.equal(protection.verifyToken(invalid, session), false)
    }

    for (const invalidHash of [undefined, null, 123, '', 'g'.repeat(64)]) {
        assert.equal(protection.verifyToken(token, {
            ...session,
            csrfTokenHash: invalidHash,
        }), false)
    }

    for (const invalidSession of [undefined, null, {}, []]) {
        assert.equal(protection.verifyToken(token, invalidSession), false)
    }
})

test('rejects invalid server keys and context identifiers', () => {
    for (const secret of [
        undefined, null, 123, '',
        '11'.repeat(31), '11'.repeat(33), 'zz'.repeat(32),
    ]) {
        assert.throws(() => createCsrfProtection(secret), TypeError)
    }

    for (const invalidId of [undefined, null, 123, '', 'student_demo']) {
        assert.throws(() => protection.createToken({
            ...context,
            sessionId: invalidId,
        }), TypeError)

        assert.throws(() => protection.createToken({
            ...context,
            userId: invalidId,
        }), TypeError)
    }
})