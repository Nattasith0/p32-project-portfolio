import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'

// ใช้ client เฉพาะสำหรับการตรวจนี้; CLI เป็นผู้ปิด connection เมื่อเสร็จ
export async function checkRoleChangeDatabase(
  client,
  { createOperation, forbiddenCode, onStep = () => {} },
) {
  if (typeof createOperation !== 'function' || typeof forbiddenCode !== 'string') {
    throw new TypeError('A role change check operation and error code are required')
  }
  const query = (text, values) =>
    client.query({
      text,
      values,
      query_timeout: 10000,
    })
  const changeUserRole = createOperation({ query })
  if (typeof changeUserRole !== 'function') {
    throw new TypeError('A role change check function is required')
  }
  const requestIds = Array.from({ length: 5 }, () => randomUUID())

  onStep('connection timeouts')
  await query("SET statement_timeout = '5s'")
  await query("SET lock_timeout = '2s'")

  onStep('database target')
  const target = (
    await query(`
    SELECT current_user AS db_user, current_database() AS db_name,
           current_setting('is_superuser')::boolean AS is_superuser,
           host(inet_server_addr()) AS server_address
  `)
  ).rows[0]
  assert.equal(target.db_user, 'p32_app')
  assert.equal(target.db_name, 'p32_dev')
  assert.equal(target.is_superuser, false)
  assert.ok(['127.0.0.1', '::1'].includes(target.server_address))

  const readRoles = async (userIds) =>
    (
      await query(
        `
    SELECT user_id, role_code, assigned_by, assigned_at
    FROM p32.user_roles
    WHERE user_id = ANY($1::uuid[])
    ORDER BY user_id, role_code
  `,
        [userIds],
      )
    ).rows
  const countAudits = async () =>
    (
      await query(
        `
    SELECT count(*)::integer AS count
    FROM p32.user_role_audit
    WHERE request_id = ANY($1::uuid[])
  `,
        [requestIds],
      )
    ).rows[0].count

  let userIds
  let beforeRoles

  onStep('begin rollback-only transaction')
  await query('BEGIN ISOLATION LEVEL READ COMMITTED')

  try {
    onStep('role-change lock')
    const lock = await query('SELECT pg_try_advisory_xact_lock(32, 1) AS acquired')
    assert.equal(lock.rows[0].acquired, true)

    onStep('demo account guards')
    const users = (
      await query(
        `
      SELECT user_id, username, is_active,
             email_verified_at IS NOT NULL AS verified
      FROM p32.users
      WHERE username IN ($1, $2)
    `,
        ['admin_demo', 'student_demo'],
      )
    ).rows
    assert.equal(users.length, 2)
    const admin = users.find((user) => user.username === 'admin_demo')
    const student = users.find((user) => user.username === 'student_demo')
    assert.ok(admin?.is_active && admin.verified)
    assert.ok(student?.is_active && student.verified)

    userIds = [admin.user_id, student.user_id]
    beforeRoles = await readRoles(userIds)
    assert.ok(
      beforeRoles.some(
        (row) => row.user_id === admin.user_id && row.role_code === 'system_admin',
      ),
    )
    assert.ok(
      beforeRoles.some(
        (row) => row.user_id === student.user_id && row.role_code === 'student',
      ),
    )
    assert.ok(
      !beforeRoles.some(
        (row) =>
          row.user_id === student.user_id &&
          ['advisor', 'system_admin'].includes(row.role_code),
      ),
    )
    assert.equal(await countAudits(), 0)

    const input = {
      actorUserId: admin.user_id,
      targetUserId: student.user_id,
      roleCode: 'advisor',
      action: 'assign',
      reason: 'ตรวจการเปลี่ยนบทบาทใน transaction ที่จะ rollback',
      requestId: requestIds[0],
    }

    onStep('assign and verify audit')
    const assigned = await changeUserRole(input)
    assert.equal(assigned.changed, true)
    const role = (await readRoles(userIds)).find(
      (row) => row.user_id === student.user_id && row.role_code === 'advisor',
    )
    assert.equal(role?.assigned_by, admin.user_id)
    const event = (
      await query(
        `
      SELECT target_user_id, actor_user_id, role_code, action, reason, request_id
      FROM p32.user_role_audit WHERE audit_id = $1
    `,
        [assigned.auditId],
      )
    ).rows[0]
    assert.deepEqual(event, {
      target_user_id: student.user_id,
      actor_user_id: admin.user_id,
      role_code: 'advisor',
      action: 'assign',
      reason: input.reason,
      request_id: requestIds[0],
    })
    const rolesAfterAssign = await readRoles(userIds)

    onStep('repeated assign is no-op')
    assert.deepEqual(
      await changeUserRole({
        ...input,
        requestId: requestIds[1],
      }),
      { changed: false, auditId: null },
    )
    assert.deepEqual(await readRoles(userIds), rolesAfterAssign)
    assert.equal(await countAudits(), 1)

    onStep('revoke and repeated revoke')
    const revoked = await changeUserRole({
      ...input,
      action: 'revoke',
      requestId: requestIds[2],
    })
    assert.equal(revoked.changed, true)
    assert.deepEqual(
      await changeUserRole({
        ...input,
        action: 'revoke',
        requestId: requestIds[3],
      }),
      { changed: false, auditId: null },
    )
    assert.deepEqual(await readRoles(userIds), beforeRoles)
    const auditEvents = (
      await query(
        `
      SELECT action, request_id FROM p32.user_role_audit
      WHERE request_id = ANY($1::uuid[]) ORDER BY occurred_at, audit_id
    `,
        [requestIds],
      )
    ).rows
    assert.deepEqual(auditEvents, [
      { action: 'assign', request_id: requestIds[0] },
      { action: 'revoke', request_id: requestIds[2] },
    ])

    onStep('database rejection passes through the operation')
    await query('SAVEPOINT before_forbidden_actor')
    await assert.rejects(
      changeUserRole({
        ...input,
        actorUserId: student.user_id,
        requestId: requestIds[4],
      }),
      (error) => error.code === forbiddenCode,
    )
    await query('ROLLBACK TO SAVEPOINT before_forbidden_actor')
    await query('RELEASE SAVEPOINT before_forbidden_actor')
    assert.equal(await countAudits(), 2)
    assert.deepEqual(await readRoles(userIds), beforeRoles)
  } finally {
    // ไม่มี COMMIT ในสคริปต์นี้ และใช้ client ตัวเดิมทุกคำสั่ง
    await query('ROLLBACK')
  }

  onStep('rollback cleanup')
  assert.equal(await countAudits(), 0)
  assert.deepEqual(await readRoles(userIds), beforeRoles)
}
