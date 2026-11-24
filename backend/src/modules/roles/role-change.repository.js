const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export function createRoleChangeRepository(database) {
  if (typeof database?.query !== 'function') {
    throw new TypeError('A database query executor is required')
  }

  async function changeUserRole({
    actorUserId,
    targetUserId,
    roleCode,
    action,
    reason,
    requestId,
  }) {
    const result = await database.query(
      `
        SELECT changed, audit_id
        FROM p32.change_user_role(
          $1::uuid, $2::uuid, $3::text,
          $4::text, $5::text, $6::uuid
        )
      `,
      [actorUserId, targetUserId, roleCode, action, reason, requestId],
    )

    if (!Array.isArray(result?.rows) || result.rows.length !== 1) {
      throw new TypeError('Invalid role change result')
    }

    const row = result.rows[0]
    const validAuditId = typeof row?.audit_id === 'string'
      && row.audit_id.length === 36
      && UUID_PATTERN.test(row.audit_id)

    if (
      !row || Array.isArray(row) || typeof row.changed !== 'boolean'
      || (row.changed && !validAuditId)
      || (!row.changed && row.audit_id !== null)
    ) {
      throw new TypeError('Invalid role change result')
    }

    return { changed: row.changed, auditId: row.audit_id }
  }

  return { changeUserRole }
}