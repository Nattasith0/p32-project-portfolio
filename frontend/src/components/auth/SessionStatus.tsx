import type { SessionState } from '../../types/auth'

export default function SessionStatus({ status, user }: SessionState) {
  if (status === 'loading') {
    return <p role="status">กำลังตรวจสอบสถานะผู้ใช้...</p>
  }

  if (status === 'error') {
    return <p role="alert">ยังไม่สามารถตรวจสอบสถานะผู้ใช้ได้</p>
  }

  if (status === 'unauthenticated') {
    return <p role="status">สถานะบัญชี: ยังไม่ได้เข้าสู่ระบบ</p>
  }

  return <p role="status">เข้าสู่ระบบแล้ว: {user.displayName}</p>
}