import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createUserSearchRepository } from '../../src/modules/users/user-search.repository.js'
import {
  createUserSearchService,
  UserSearchError,
} from '../../src/modules/users/user-search.service.js'

const publicUser = (row) => ({
  userId: row.user_id,
  username: row.username,
  displayName: row.display_name,
  isActive: row.is_active,
  emailVerified: row.email_verified,
})

// ผู้เรียกต้องเปิด transaction แบบ REPEATABLE READ READ ONLY และกำหนด timeout แล้ว
export async function checkUserSearchDatabase(database, setCheckName) {
  setCheckName('database target and read-only transaction')
  const target = await database.query(`
    SELECT current_user AS db_user, current_database() AS db_name,
           current_setting('is_superuser')::boolean AS is_superuser,
           current_setting('transaction_read_only')::boolean AS read_only,
           current_setting('transaction_isolation') AS isolation,
           host(inet_server_addr()) AS server_address
  `)
  assert.equal(target.rows.length, 1)
  assert.equal(target.rows[0].db_user, 'p32_app')
  assert.equal(target.rows[0].db_name, 'p32_dev')
  assert.equal(target.rows[0].is_superuser, false)
  assert.equal(target.rows[0].read_only, true)
  assert.equal(target.rows[0].isolation, 'repeatable read')
  assert.ok(['127.0.0.1', '::1'].includes(target.rows[0].server_address))

  let searchQueries = 0
  const repository = createUserSearchRepository({
    query(sql, values) {
      searchQueries += 1
      return database.query(sql, values)
    },
  })
  const service = createUserSearchService({ userSearchRepository: repository })

  setCheckName('existing development demo accounts')
  const demo = await database.query(
    `
    SELECT user_id, username, display_name, is_active,
           email_verified_at IS NOT NULL AS email_verified
    FROM p32.users
    WHERE username IN ($1, $2)
    ORDER BY user_id
  `,
    ['admin_demo', 'student_demo'],
  )
  assert.equal(demo.rows.length, 2)
  for (const row of demo.rows) {
    assert.equal(row.is_active, true)
    assert.equal(row.email_verified, true)
    const result = await service.searchUsers({ q: row.username })
    assert.deepEqual(
      result.users.find((user) => user.userId === row.user_id),
      publicUser(row),
    )
  }

  setCheckName('case-insensitive search and minimal public fields')
  const mixedCase = await service.searchUsers({ q: 'StUdEnT_DeMo' })
  assert.ok(mixedCase.users.some((user) => user.username === 'student_demo'))
  for (const user of mixedCase.users) {
    assert.deepEqual(Object.keys(user).sort(), [
      'displayName',
      'emailVerified',
      'isActive',
      'userId',
      'username',
    ])
  }

  setCheckName('bounded reference fixtures for pagination')
  const expected = await database.query(`
    SELECT user_id, username, display_name, is_active,
           email_verified_at IS NOT NULL AS email_verified
    FROM p32.users
    WHERE username ILIKE '%demo%' OR display_name ILIKE '%demo%'
    ORDER BY user_id
    LIMIT 51
  `)
  // ต้องมีอย่างน้อยสองบัญชี และจำกัดขนาด fixture เพื่อไม่ไล่อ่านทั้งฐาน
  assert.ok(expected.rows.length >= 2 && expected.rows.length <= 50)

  setCheckName('cursor pagination without skipped or duplicated accounts')
  const users = []
  let after
  let completed = false
  for (let page = 0; page < 50; page += 1) {
    const result = await service.searchUsers({
      q: 'demo',
      limit: '1',
      ...(after ? { after } : {}),
    })
    assert.ok(result.users.length <= 1)
    users.push(...result.users)
    if (result.nextCursor === null) {
      completed = true
      break
    }
    assert.equal(result.nextCursor, result.users[0].userId)
    after = result.nextCursor
  }
  assert.equal(completed, true)
  assert.deepEqual(users, expected.rows.map(publicUser))

  setCheckName('literal wildcard and SQL-looking search values')
  for (const q of ['%%', '__', 'a!b', String.raw`a\b`, "x' OR 1=1 --"]) {
    // ใช้ strpos เป็น reference อิสระจาก LIKE escaping สำหรับข้อความชุดนี้
    const reference = await database.query(
      `
      SELECT user_id FROM p32.users
      WHERE strpos(username, $1) > 0 OR strpos(display_name, $1) > 0
      ORDER BY user_id LIMIT 51
    `,
      [q],
    )
    assert.ok(reference.rows.length <= 50)
    const result = await service.searchUsers({ q, limit: '50' })
    assert.deepEqual(
      result.users.map((user) => user.userId),
      reference.rows.map((row) => row.user_id),
    )
    assert.equal(result.nextCursor, null)
  }

  setCheckName('no-match search')
  const missingTerm = randomUUID()
  const matching = await database.query(
    `
    SELECT 1 FROM p32.users
    WHERE username ILIKE $1 OR display_name ILIKE $1 LIMIT 1
  `,
    [`%${missingTerm}%`],
  )
  assert.equal(matching.rows.length, 0)
  assert.deepEqual(await service.searchUsers({ q: missingTerm }), {
    users: [],
    nextCursor: null,
  })

  setCheckName('invalid query rejected before database lookup')
  const queriesBefore = searchQueries
  await assert.rejects(service.searchUsers({ q: 'demo', limit: '51' }), UserSearchError)
  await assert.rejects(
    service.searchUsers({ q: 'demo', after: 'invalid' }),
    UserSearchError,
  )
  assert.equal(searchQueries, queriesBefore)
}
