import test from 'node:test'
import assert from 'node:assert/strict'
import { hashPassword } from '../src/security/password.js'
import { createAuthService } from '../src/modules/auth/auth.service.js'

// ข้อมูลสมมติสำหรับทดสอบเท่านั้น
const password = ' Example password only for testing! '
const dummyPassword = 'Dummy password only for testing!'

const passwordHash = await hashPassword(password)
const dummyPasswordHash = await hashPassword(dummyPassword)

const credentials = {
    username: 'student_demo',
    password,
}

const activeUser = {
    user_id: '00000000-0000-4000-8000-000000000099',
    username: 'student_demo',
    display_name: 'ผู้ใช้ทดสอบ',
    password_hash: passwordHash,
    is_active: true,
    email_verified_at: new Date('2026-01-01T00:00:00Z'),
}

function serviceFor(user) {
    return createAuthService({
        findUserByUsername: async (username) => {
            assert.equal(username, credentials.username)
            return user
        },
        dummyPasswordHash,
    })
}

test('valid credentials return only safe user fields', async () => {
    const service = serviceFor(activeUser)

    const result = await service.authenticateCredentials(credentials)

    assert.deepEqual(result, {
        userId: activeUser.user_id,
        username: activeUser.username,
        displayName: activeUser.display_name,
    })
})

test('wrong password is rejected', async () => {
    const service = serviceFor(activeUser)

    const result = await service.authenticateCredentials({
        ...credentials,
        password: 'Wrong password!',
    })

    assert.equal(result, null)
})

test('password spaces remain significant in the service', async () => {
    const service = serviceFor(activeUser)

    const result = await service.authenticateCredentials({
        ...credentials,
        password: password.trim(),
    })

    assert.equal(result, null)
})

test('missing account is rejected even when dummy password matches', async () => {
    const service = serviceFor(null)

    const result = await service.authenticateCredentials({
        ...credentials,
        password: dummyPassword,
    })

    assert.equal(result, null)
})

test('inactive account is rejected with the correct password', async () => {
    const service = serviceFor({
        ...activeUser,
        is_active: false,
    })

    assert.equal(
        await service.authenticateCredentials(credentials),
        null
    )
})

test('unverified account is rejected with the correct password', async () => {
    const service = serviceFor({
        ...activeUser,
        email_verified_at: null,
    })

    assert.equal(
        await service.authenticateCredentials(credentials),
        null
    )
})

test('repository failure propagates instead of authenticating', async () => {
    const databaseError = new Error('Simulated database failure')

    const service = createAuthService({
        findUserByUsername: async () => {
            throw databaseError
        },
        dummyPasswordHash,
    })

    await assert.rejects(
        service.authenticateCredentials(credentials),
        (error) => error === databaseError
    )
})