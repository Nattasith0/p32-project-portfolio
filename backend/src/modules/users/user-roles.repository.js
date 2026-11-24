import { parseUserRolesUserId } from './user-roles.validation.js'

export function createUserRolesRepository(database) {
  if (typeof database?.query !== 'function') {
    throw new TypeError('A database query executor is required')
  }

  async function findUserRolesByUserId(userId) {
    const targetId = parseUserRolesUserId(userId)
    if (targetId === null) throw new TypeError('A valid target user ID is required')

    const result = await database.query(
      `
        SELECT u.user_id, u.username, u.display_name, u.is_active,
               u.email_verified_at IS NOT NULL AS email_verified,
               ur.role_code, r.role_name
        FROM p32.users AS u
        LEFT JOIN p32.user_roles AS ur ON ur.user_id = u.user_id
        LEFT JOIN p32.roles AS r ON r.role_code = ur.role_code
        WHERE u.user_id = $1::uuid
        ORDER BY ur.role_code ASC
      `,
      [targetId],
    )

    // LEFT JOIN แยกบัญชีไม่มีบทบาท (แถวที่ role เป็น null) จากไม่พบบัญชี (ไม่มีแถว)
    // ไม่กรอง inactive/unverified เพื่อให้ผู้ดูแลตรวจและถอนสิทธิ์ได้
    if (!Array.isArray(result?.rows)) throw new TypeError('Invalid user roles result')
    return result.rows
  }

  return { findUserRolesByUserId }
}
