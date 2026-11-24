import { ROLE_CODES } from '../authorization/authorization.service.js'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const INPUT_FIELDS = ['targetUserId', 'roleCode', 'action', 'reason']

// ตรวจรูปแบบรหัสเท่านั้น ไม่ได้ตรวจตัวตนหรือสิทธิ์ของเจ้าของรหัส
export function parseRoleChangeUuid(value) {
  if (typeof value !== 'string' || value.length !== 36 || !UUID_PATTERN.test(value)) {
    return null
  }

  return value.toLowerCase()
}

export function parseRoleChangeInput(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return null
  }

  const fields = Object.keys(input)
  if (
    fields.length !== INPUT_FIELDS.length ||
    INPUT_FIELDS.some((field) => !Object.hasOwn(input, field))
  ) {
    return null
  }

  const targetUserId = parseRoleChangeUuid(input.targetUserId)
  if (
    targetUserId === null ||
    typeof input.roleCode !== 'string' ||
    !ROLE_CODES.includes(input.roleCode) ||
    !['assign', 'revoke'].includes(input.action) ||
    typeof input.reason !== 'string'
  ) {
    return null
  }

  // PostgreSQL text ไม่รับ NUL; ป้องกัน UTF-16 ที่แปลงเป็น UTF-8 ไม่ตรงข้อมูลเดิม
  if (input.reason.includes('\0') || !input.reason.isWellFormed()) {
    return null
  }

  const reason = input.reason.trim()
  const reasonLength = Array.from(reason).length
  if (
    reasonLength < 1 ||
    reasonLength > 500 ||
    !/[^\p{White_Space}\uFEFF]/u.test(reason)
  ) {
    return null
  }

  return { targetUserId, roleCode: input.roleCode, action: input.action, reason }
}