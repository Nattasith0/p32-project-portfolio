export function up(pgm) {
    pgm.sql(`
    CREATE TABLE p32.users (
      user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username TEXT NOT NULL,
      email TEXT NOT NULL,
      email_verified_at TIMESTAMPTZ,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      is_active BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

      CONSTRAINT users_username_unique
        UNIQUE (username),

              CONSTRAINT users_email_unique
        UNIQUE (email),

      CONSTRAINT users_email_not_blank
        CHECK (
          email = btrim(email)
          AND email <> ''
        ),

      CONSTRAINT users_active_requires_verified_email
        CHECK (
          NOT is_active
          OR email_verified_at IS NOT NULL
        ),

      CONSTRAINT users_username_normalized
        CHECK (
          username = lower(btrim(username))
          AND username <> ''
        ),

      CONSTRAINT users_display_name_not_blank
        CHECK (btrim(display_name) <> ''),

      CONSTRAINT users_password_hash_not_blank
        CHECK (btrim(password_hash) <> '')
    );

    REVOKE ALL ON TABLE p32.users FROM PUBLIC;

    GRANT SELECT, INSERT, UPDATE
      ON TABLE p32.users
      TO p32_app;
  `)
}

export function down(pgm) {
    pgm.sql('DROP TABLE p32.users RESTRICT;')
}