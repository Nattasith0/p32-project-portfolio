import argon2 from 'argon2'

const PASSWORD_HASH_OPTIONS = {
    type: argon2.argon2id,
    memoryCost: 64 * 1024, // หน่วย KiB เท่ากับ 64 MiB
    timeCost: 3,
    parallelism: 1,
}

function assertNonEmptyString(value, fieldName) {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${fieldName} must be a non-empty string`)
    }
}

export async function hashPassword(password) {
    assertNonEmptyString(password, 'password')

    return argon2.hash(password, PASSWORD_HASH_OPTIONS)
}

export async function verifyPassword(passwordHash, password) {
    assertNonEmptyString(passwordHash, 'passwordHash')
    assertNonEmptyString(password, 'password')

    return argon2.verify(passwordHash, password)
}