export function createSessionAuthService({
  jwtService,
  sessionRepository,
}) {
  if (typeof jwtService?.verifySession !== 'function') {
    throw new TypeError('A JWT service is required')
  }

  if (typeof sessionRepository?.findActiveSession !== 'function') {
    throw new TypeError('A session repository is required')
  }

  async function authenticateSessionToken(token) {
    const verified = await jwtService.verifySession(token)

    if (!verified) {
      return null
    }

    const active = await sessionRepository.findActiveSession({
      sessionId: verified.sessionId,
      userId: verified.userId,
    })

    if (!active) {
      return null
    }

    if (
      active.session_id !== verified.sessionId ||
      active.user_id !== verified.userId ||
      active.expires_at.getTime() !== verified.expiresAt.getTime()
    ) {
      return null
    }

    // ข้อมูลสำหรับใช้ภายใน Backend
    return {
      userId: active.user_id,
      username: active.username,
      displayName: active.display_name,
      sessionId: active.session_id,
      expiresAt: active.expires_at,
    }
  }

  return { authenticateSessionToken }
}