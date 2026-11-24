export function createUserSearchRepository(database) {
  if (typeof database?.query !== 'function') {
    throw new TypeError('A database query executor is required')
  }

  // service จะส่งค่าที่ผ่าน parseUserSearchQuery แล้วเข้ามา
  async function searchUsers({ searchTerm, limit, after = null }) {
    if (
      typeof searchTerm !== 'string' ||
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 50
    ) {
      throw new TypeError('Validated user search values are required')
    }

    // ESCAPE '!' ทำให้ %, _ และ ! ในคำค้นเป็นตัวอักษร ไม่ใช่ wildcard ของผู้ใช้
    const pattern = '%' + searchTerm.replace(/[!%_]/g, '!$&') + '%'
    const result = await database.query(
      `
        SELECT user_id, username, display_name, is_active,
               email_verified_at IS NOT NULL AS email_verified
        FROM p32.users
        WHERE (username ILIKE $1 ESCAPE '!' OR display_name ILIKE $1 ESCAPE '!')
          AND ($2::uuid IS NULL OR user_id > $2::uuid)
        ORDER BY user_id ASC
        LIMIT $3
      `,
      // อ่านเผื่อหนึ่งแถวเพื่อให้ service ทราบว่ามีหน้าถัดไป โดยไม่ COUNT ทั้งตาราง
      [pattern, after, limit + 1],
    )

    if (!Array.isArray(result?.rows)) throw new TypeError('Invalid user search result')
    return result.rows
  }

  return { searchUsers }
}
