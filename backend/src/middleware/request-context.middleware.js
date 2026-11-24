import { randomUUID } from 'node:crypto'

export function requestContext(request, response, next) {
    const requestId = randomUUID()

    request.requestId = requestId
    response.set('X-Request-Id', requestId)

    return next()
}