import { MAX_PASSWORD_LENGTH } from '../../security/password-policy.js'

const MAX_USERNAME_LENGTH = 128

export function parseLoginInput(input) {
    if (
        input === null ||
        typeof input !== 'object' ||
        Array.isArray(input)
    ) {
        return null
    }

    const fields = Object.keys(input)

    if (
        fields.length !== 2 ||
        !fields.includes('username') ||
        !fields.includes('password')
    ) {
        return null
    }

    if (
        typeof input.username !== 'string' ||
        typeof input.password !== 'string'
    ) {
        return null
    }

    const username = input.username.trim().toLowerCase()
    const password = input.password

    const usernameLength = Array.from(username).length
    const passwordLength = Array.from(password).length

    if (
        usernameLength === 0 ||
        usernameLength > MAX_USERNAME_LENGTH ||
        passwordLength === 0 ||
        passwordLength > MAX_PASSWORD_LENGTH
    ) {
        return null
    }

    return { username, password }
}