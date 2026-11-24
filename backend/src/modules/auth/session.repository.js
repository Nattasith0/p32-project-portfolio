export function createSessionRepository(database) {
    if (typeof database?.query !== 'function') {
        throw new TypeError('A database query executor is required')
    }

    async function createSession({
        sessionId,
        userId,
        csrfTokenHash,
        expiresAt,
    }) {
        const result = await database.query(
            `
        INSERT INTO p32.auth_sessions (
          session_id,
          user_id,
          csrf_token_hash,
          expires_at
        )
        VALUES ($1, $2, $3, $4)
        RETURNING
          session_id,
          user_id,
          created_at,
          expires_at,
          revoked_at
      `,
            [sessionId, userId, csrfTokenHash, expiresAt]
        )

        return result.rows[0]
    }

    async function findActiveSession({ sessionId, userId }) {
        const result = await database.query(
            `
        SELECT
          s.session_id,
          s.user_id,
          s.csrf_token_hash,
          s.created_at,
          s.expires_at,
          u.username,
          u.display_name
        FROM p32.auth_sessions AS s
        JOIN p32.users AS u
          ON u.user_id = s.user_id
        WHERE s.session_id = $1
          AND s.user_id = $2
          AND s.revoked_at IS NULL
          AND s.expires_at > statement_timestamp()
          AND u.is_active = TRUE
          AND u.email_verified_at IS NOT NULL
      `,
            [sessionId, userId]
        )

        return result.rows[0] ?? null
    }

    async function revokeSession({ sessionId, userId }) {
        const result = await database.query(
            `
        UPDATE p32.auth_sessions
        SET revoked_at = statement_timestamp()
        WHERE session_id = $1
          AND user_id = $2
          AND revoked_at IS NULL
      `,
            [sessionId, userId]
        )

        return result.rowCount === 1
    }

    return { createSession, findActiveSession, revokeSession }
}