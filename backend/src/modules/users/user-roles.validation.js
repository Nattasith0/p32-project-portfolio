const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

// ตรวจรหัสบัญชีที่เลือกเท่านั้น สิทธิ์ผู้เรียกต้องตรวจจาก session แยกต่างหาก
export function parseUserRolesUserId(value) {
  if (typeof value !== 'string' || value.length !== 36 || !UUID_PATTERN.test(value)) {
    return null
  }
  return value.toLowerCase()
}
