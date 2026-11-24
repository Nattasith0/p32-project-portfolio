import { UserSearchError } from './user-search.service.js'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const isUuid = (value) =>
  typeof value === 'string' && value.length === 36 && UUID_PATTERN.test(value)
const isText = (value) => typeof value === 'string' && value.trim().length > 0

function publicPage(result) {
  if (
    !result ||
    Array.isArray(result) ||
    !Array.isArray(result.users) ||
    result.users.length > 50
  ) {
    throw new TypeError('Invalid user search response')
  }

  let previousId = null
  const users = []
  for (const user of result.users) {
    if (
      !user ||
      Array.isArray(user) ||
      !isUuid(user.userId) ||
      !isText(user.username) ||
      !isText(user.displayName) ||
      typeof user.isActive !== 'boolean' ||
      typeof user.emailVerified !== 'boolean' ||
      (user.isActive && !user.emailVerified) ||
      (previousId !== null && user.userId <= previousId)
    ) {
      throw new TypeError('Invalid user search response user')
    }
    previousId = user.userId
    // ระบุฟิลด์ HTTP ชัดเจน แม้ Service ในอนาคตจะเพิ่มข้อมูลภายใน
    users.push({
      userId: user.userId,
      username: user.username,
      displayName: user.displayName,
      isActive: user.isActive,
      emailVerified: user.emailVerified,
    })
  }

  const nextCursor = result.nextCursor
  if (
    nextCursor !== null &&
    (!isUuid(nextCursor) || users.length === 0 || nextCursor !== previousId)
  ) {
    throw new TypeError('Invalid user search response cursor')
  }
  return { users, nextCursor }
}

export function createUserSearchController({ userSearchService } = {}) {
  if (typeof userSearchService?.searchUsers !== 'function') {
    throw new TypeError('A user search service is required')
  }

  // Router ต้องตรวจ session/system_admin ก่อนเรียก handler นี้
  async function searchUsers(request, response) {
    response.set('Cache-Control', 'no-store')
    if (!isUuid(request.requestId))
      throw new TypeError('A server request ID is required')

    let result
    try {
      result = await userSearchService.searchUsers(request.query)
    } catch (error) {
      if (
        !(error instanceof UserSearchError) ||
        error.code !== 'INVALID_USER_SEARCH_INPUT'
      )
        throw error
      return response.status(400).json({
        code: 'INVALID_USER_SEARCH_INPUT',
        message: 'ข้อมูลการค้นหาบัญชีไม่ถูกต้อง',
        request_id: request.requestId,
      })
    }

    const page = publicPage(result)
    return response.status(200).json(page)
  }

  return { searchUsers }
}
