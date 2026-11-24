export function createAuthorizationRepository(database) {
  if (typeof database?.query !== 'function') {
    throw new TypeError('A database query executor is required')
  }

  async function findRoleCodesByUserId(userId) {
    const result = await database.query(
      `
        SELECT ur.role_code
        FROM p32.user_roles AS ur
        JOIN p32.users AS u ON u.user_id = ur.user_id
        WHERE ur.user_id = $1
          AND u.is_active = TRUE
          AND u.email_verified_at IS NOT NULL
        ORDER BY ur.role_code
      `,
      [userId],
    )

    return result.rows.map((row) => row.role_code)
  }

  return { findRoleCodesByUserId }
}