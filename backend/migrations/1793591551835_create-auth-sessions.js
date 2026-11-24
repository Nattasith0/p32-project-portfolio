export function up(pgm) {
    pgm.sql(`
    CREATE TABLE p32.auth_sessions (
      session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL,
      csrf_token_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ NOT NULL,
      revoked_at TIMESTAMPTZ,

      CONSTRAINT auth_sessions_user_fk
        FOREIGN KEY (user_id)
        REFERENCES p32.users (user_id)
        ON DELETE RESTRICT,

      CONSTRAINT auth_sessions_csrf_hash_format
        CHECK (csrf_token_hash ~ '^[0-9a-f]{64}$'),

      CONSTRAINT auth_sessions_expiration_valid
        CHECK (
          isfinite(created_at)
          AND isfinite(expires_at)
          AND expires_at > created_at
        ),

      CONSTRAINT auth_sessions_revocation_valid
        CHECK (
          revoked_at IS NULL
          OR (
            isfinite(revoked_at)
            AND revoked_at >= created_at
          )
        )
    );

    CREATE INDEX auth_sessions_unrevoked_user_idx
      ON p32.auth_sessions (user_id)
      WHERE revoked_at IS NULL;

    REVOKE ALL ON TABLE p32.auth_sessions
      FROM PUBLIC, p32_app;

    GRANT SELECT, INSERT
      ON TABLE p32.auth_sessions
      TO p32_app;

    GRANT UPDATE (revoked_at)
      ON TABLE p32.auth_sessions
      TO p32_app;
  `)
}

export function down(pgm) {
    pgm.sql('DROP TABLE p32.auth_sessions RESTRICT;')
}