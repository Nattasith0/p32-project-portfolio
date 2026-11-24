import { verifyPassword } from '../../security/password.js'

export function createAuthService({
    findUserByUsername,
    dummyPasswordHash,
}) {
    if (
        typeof findUserByUsername !== 'function' ||
        typeof dummyPasswordHash !== 'string' ||
        dummyPasswordHash.length === 0
    ) {
        throw new TypeError('Invalid auth service configuration')
    }

    // รับข้อมูลที่ผ่าน parseLoginInput แล้ว
    async function authenticateCredentials({ username, password }) {
        const user = await findUserByUsername(username)

        const passwordHash = user
            ? user.password_hash
            : dummyPasswordHash

        const passwordMatches = await verifyPassword(
            passwordHash,
            password
        )

        if (
            !user ||
            !passwordMatches ||
            user.is_active !== true ||
            user.email_verified_at == null
        ) {
            return null
        }

        return {
            userId: user.user_id,
            username: user.username,
            displayName: user.display_name,
        }
    }

    return { authenticateCredentials }
}