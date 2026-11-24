export function createLogoutController({
    sessionRepository,
    sessionCookie,
}) {
    if (typeof sessionRepository?.revokeSession !== 'function') {
        throw new TypeError('A session repository is required')
    }

    if (typeof sessionCookie?.clearSessionCookie !== 'function') {
        throw new TypeError('A session cookie helper is required')
    }

    // ต้องผ่าน Origin, requireSession และ requireCsrf ก่อนเรียก
    async function logout(request, response) {
        response.set('Cache-Control', 'no-store')

        await sessionRepository.revokeSession({
            sessionId: request.auth.sessionId,
            userId: request.auth.userId,
        })

        sessionCookie.clearSessionCookie(response)

        return response.status(204).end()
    }

    return { logout }
}