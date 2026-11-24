const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const ALLOWED_FIELDS = new Set(['q', 'limit', 'after'])

export function parseUserSearchQuery(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) return null
  if (
    !Object.hasOwn(input, 'q') ||
    Object.keys(input).some((key) => !ALLOWED_FIELDS.has(key))
  ) {
    return null
  }

  if (typeof input.q !== 'string' || input.q.includes('\0') || !input.q.isWellFormed()) {
    return null
  }
  const searchTerm = input.q.trim()
  const length = Array.from(searchTerm).length
  if (length < 2 || length > 100 || !/[^\p{White_Space}\uFEFF]/u.test(searchTerm)) {
    return null
  }

  let limit = 20
  if (Object.hasOwn(input, 'limit')) {
    if (typeof input.limit !== 'string' || input.limit.length > 2) return null
    limit = Number(input.limit)
    if (
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 50 ||
      String(limit) !== input.limit
    ) {
      return null
    }
  }

  let after = null
  if (Object.hasOwn(input, 'after')) {
    if (
      typeof input.after !== 'string' ||
      input.after.length !== 36 ||
      !UUID_PATTERN.test(input.after)
    ) {
      return null
    }
    after = input.after.toLowerCase()
  }

  return { searchTerm, limit, after }
}
