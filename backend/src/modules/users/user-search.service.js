import { parseUserSearchQuery } from './user-search.validation.js'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export class UserSearchError extends Error {
  constructor() {
    super('Invalid user search input')
    this.name = 'UserSearchError'
    this.code = 'INVALID_USER_SEARCH_INPUT'
  }
}

function isDisplayText(value) {
  return typeof value === 'string' && value.trim().length > 0
}

export function createUserSearchService({ userSearchRepository } = {}) {
  if (typeof userSearchRepository?.searchUsers !== 'function') {
    throw new TypeError('A user search repository is required')
  }

  async function searchUsers(query) {
    const search = parseUserSearchQuery(query)
    if (search === null) throw new UserSearchError()

    const rows = await userSearchRepository.searchUsers({ ...search })
    if (!Array.isArray(rows) || rows.length > search.limit + 1) {
      throw new TypeError('Invalid user search result')
    }

    let previousId = search.after
    const users = []
    // ตรวจแถวเผื่อหน้าถัดไปด้วย ก่อนตัดออกจากข้อมูลที่จะส่งให้หน้าจอ
    for (const row of rows) {
      if (
        !row ||
        Array.isArray(row) ||
        typeof row.user_id !== 'string' ||
        row.user_id.length !== 36 ||
        !UUID_PATTERN.test(row.user_id) ||
        !isDisplayText(row.username) ||
        !isDisplayText(row.display_name) ||
        typeof row.is_active !== 'boolean' ||
        typeof row.email_verified !== 'boolean' ||
        (row.is_active && !row.email_verified)
      ) {
        throw new TypeError('Invalid user search row')
      }

      const userId = row.user_id.toLowerCase()
      if (previousId !== null && userId <= previousId) {
        throw new TypeError('Invalid user search order')
      }
      previousId = userId

      // สร้าง DTO ใหม่ ไม่ส่ง raw row หรือฟิลด์ส่วนตัวที่อาจติดมาจาก repository
      users.push({
        userId,
        username: row.username,
        displayName: row.display_name,
        isActive: row.is_active,
        emailVerified: row.email_verified,
      })
    }

    const hasNextPage = users.length > search.limit
    const page = users.slice(0, search.limit)
    return {
      users: page,
      // ใช้แถวสุดท้ายที่คืน เพื่อไม่ข้ามแถว lookahead เมื่อโหลดหน้าถัดไป
      nextCursor: hasNextPage ? page[page.length - 1].userId : null,
    }
  }

  return { searchUsers }
}
