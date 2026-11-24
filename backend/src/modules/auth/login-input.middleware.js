import { createJsonBodyParser } from '../../middleware/json-body.middleware.js'
import { parseLoginInput } from './auth.validation.js'

export function createLoginJsonParser() {
  return createJsonBodyParser()
}

export function validateLoginRequest(request, response, next) {
  response.set('Cache-Control', 'no-store')
  request.loginInput = null

  const input = parseLoginInput(request.body)

  if (input === null) {
    return response.status(400).json({
      code: 'INVALID_LOGIN_INPUT',
      message: 'ข้อมูลเข้าสู่ระบบไม่ถูกต้อง',
      request_id: request.requestId,
    })
  }

  // ขั้นตรวจบัญชีรับเฉพาะข้อมูลที่ผ่าน validation แล้ว
  request.loginInput = input
  return next()
}
