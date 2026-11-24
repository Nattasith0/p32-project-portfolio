/** ข้อมูลบัญชีที่ UI ใช้ได้ ไม่รวมรหัสผ่านหรือสิทธิ์จาก client */
export type User = {
  userId: string
  username: string
  displayName: string
}

export type LoginInput = { username: string; password: string }

/** เมื่อ authenticated ต้องมี user เสมอ; สถานะอื่นต้องไม่มี user */
export type SessionState =
  | { status: 'authenticated'; user: User }
  | { status: 'loading'; user: null }
  | { status: 'unauthenticated'; user: null }
  | { status: 'error'; user: null }
