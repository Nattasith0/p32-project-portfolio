import { SignJWT, jwtVerify, errors } from 'jose'

const ALGORITHM = 'HS256'
const ISSUER = 'p32-api'
const AUDIENCE = 'p32-web'
const MAX_LIFETIME_SECONDS = 30 * 60
const MAX_TOKEN_LENGTH = 4096

const SECRET_PATTERN = /^[0-9a-f]{64}$/
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isUuid(value) {
  return typeof value === 'string' && UUID_PATTERN.test(value)
}

export function createJwtService({
  secretHex,
  now = Date.now,
}) {
  if (
    typeof secretHex !== 'string' ||
    !SECRET_PATTERN.test(secretHex)
  ) {
    throw new TypeError('JWT secret must be 64 lowercase hex characters')
  }

  if (typeof now !== 'function') {
    throw new TypeError('A clock function is required')
  }

  const key = Buffer.from(secretHex, 'hex')

  function readClock() {
    const milliseconds = now()

    if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) {
      throw new TypeError('Invalid clock value')
    }

    const date = new Date(milliseconds)

    if (!Number.isFinite(date.getTime())) {
      throw new TypeError('Invalid clock value')
    }

    return {
      date,
      seconds: Math.floor(milliseconds / 1000),
    }
  }

  async function signSession({ sessionId, userId, expiresAt }) {
    if (!isUuid(sessionId) || !isUuid(userId)) {
      throw new TypeError('Session and user UUIDs are required')
    }

    const expirationMs =
      expiresAt instanceof Date ? expiresAt.getTime() : NaN

    // ต้องตรงกับเวลาระดับวินาทีที่ Session Service กำหนด
    if (
      !Number.isSafeInteger(expirationMs) ||
      expirationMs % 1000 !== 0
    ) {
      throw new TypeError('Expiration must be a valid whole-second Date')
    }

    const issuedAt = readClock().seconds
    const expiration = expirationMs / 1000

    if (
      expiration <= issuedAt ||
      expiration - issuedAt > MAX_LIFETIME_SECONDS
    ) {
      throw new RangeError('Session expiration must be within 30 minutes')
    }

    return new SignJWT({})
      .setProtectedHeader({ alg: ALGORITHM, typ: 'JWT' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject(userId.toLowerCase())
      .setJti(sessionId.toLowerCase())
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiration)
      .sign(key)
  }

  async function verifySession(token) {
    if (
      typeof token !== 'string' ||
      token.length === 0 ||
      token.length > MAX_TOKEN_LENGTH
    ) {
      return null
    }

    const clock = readClock()
    let payload

    try {
      const result = await jwtVerify(token, key, {
        algorithms: [ALGORITHM],
        issuer: ISSUER,
        audience: AUDIENCE,
        typ: 'JWT',
        requiredClaims: ['sub', 'jti', 'iat', 'exp'],
        currentDate: clock.date,
        clockTolerance: 0,
      })

      payload = result.payload
    } catch (error) {
      if (error instanceof errors.JOSEError) {
        return null
      }

      throw error
    }

    if (
      !isUuid(payload.sub) ||
      !isUuid(payload.jti) ||
      !Number.isSafeInteger(payload.iat) ||
      !Number.isSafeInteger(payload.exp) ||
      payload.iat < 0 ||
      payload.iat > clock.seconds ||
      payload.exp <= payload.iat ||
      payload.exp - payload.iat > MAX_LIFETIME_SECONDS
    ) {
      return null
    }

    return {
      userId: payload.sub.toLowerCase(),
      sessionId: payload.jti.toLowerCase(),
      expiresAt: new Date(payload.exp * 1000),
    }
  }

  return { signSession, verifySession }
}