import test from 'node:test'
import assert from 'node:assert/strict'
import {
    hashPassword,
    verifyPassword,
} from '../src/security/password.js'

// ข้อมูลสมมติสำหรับทดสอบเท่านั้น
const demoPassword = 'P32 demo password for tests only!'

test('correct password passes and wrong password fails', async () => {
    const passwordHash = await hashPassword(demoPassword)

    assert.ok(passwordHash.startsWith('$argon2id$'))
    assert.equal(await verifyPassword(passwordHash, demoPassword), true)
    assert.equal(await verifyPassword(passwordHash, 'Wrong password!'), false)
})

test('the same password produces different usable hashes', async () => {
    const firstHash = await hashPassword(demoPassword)
    const secondHash = await hashPassword(demoPassword)

    assert.notEqual(firstHash, secondHash)
    assert.equal(await verifyPassword(firstHash, demoPassword), true)
    assert.equal(await verifyPassword(secondHash, demoPassword), true)
})

test('spaces remain part of the password', async () => {
    const password = ' P32 demo password with spaces! '
    const passwordHash = await hashPassword(password)

    assert.equal(await verifyPassword(passwordHash, password), true)
    assert.equal(await verifyPassword(passwordHash, password.trim()), false)
})

test('empty and invalid inputs are rejected', async () => {
    await assert.rejects(hashPassword(''), TypeError)
    await assert.rejects(hashPassword(null), TypeError)
    await assert.rejects(verifyPassword('', demoPassword), TypeError)
    await assert.rejects(verifyPassword('test-hash', null), TypeError)
})