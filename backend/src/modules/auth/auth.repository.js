export function createAuthRepository(database) {
    if (typeof database?.query !== 'function') {
        throw new TypeError('A database query executor is required')
    }

    async function findUserByUsername(username) {
        const result = await database.query(
            `
                SELECT user_id, username, display_name, password_hash,
                       is_active, email_verified_at
                FROM p32.users
                WHERE username = $1
            `,
            [username],
        )

        return result.rows[0] ?? null
    }

    return { findUserByUsername }
}

// คงชื่อ export เดิมสำหรับคำสั่งตรวจ repository ที่เคยใช้
// เส้นทางใหม่สร้าง repository ครั้งเดียว โดยส่ง pool/client ให้ factory
export async function findUserByUsername(username) {
    const { pool } = await import('../../database/pool.js')
    return createAuthRepository(pool).findUserByUsername(username)
}
