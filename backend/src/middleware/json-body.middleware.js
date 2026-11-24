import express from 'express'

export function createJsonBodyParser() {
  const parseJson = express.json({
    type: 'application/json',
    limit: 16 * 1024,
    strict: true,
    inflate: false,
  })

  return function jsonBodyParser(request, response, next) {
    response.set('Cache-Control', 'no-store')
    if (!request.is('application/json')) {
      return response.status(415).json({
        code: 'UNSUPPORTED_MEDIA_TYPE',
        message: 'รูปแบบข้อมูลคำขอไม่รองรับ',
        request_id: request.requestId,
      })
    }

    return parseJson(request, response, next)
  }
}
