export function up(pgm) {
  pgm.sql(`
    CREATE TABLE p32.user_role_audit (
      audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      target_user_id UUID NOT NULL,
      role_code TEXT NOT NULL,
      action TEXT NOT NULL,
      actor_user_id UUID NOT NULL,
      reason TEXT NOT NULL,
      request_id UUID NOT NULL,
      occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

      CONSTRAINT user_role_audit_target_fk
        FOREIGN KEY (target_user_id)
        REFERENCES p32.users (user_id)
        ON DELETE RESTRICT,

      CONSTRAINT user_role_audit_role_fk
        FOREIGN KEY (role_code)
        REFERENCES p32.roles (role_code)
        ON DELETE RESTRICT,

      CONSTRAINT user_role_audit_actor_fk
        FOREIGN KEY (actor_user_id)
        REFERENCES p32.users (user_id)
        ON DELETE RESTRICT,

      CONSTRAINT user_role_audit_action_valid
        CHECK (action IN ('assign', 'revoke')),

      CONSTRAINT user_role_audit_reason_valid
        CHECK (
          reason = btrim(reason)
          AND char_length(reason) BETWEEN 1 AND 500
          AND reason ~ '[^[:space:]]'
        ),

      CONSTRAINT user_role_audit_time_finite
        CHECK (isfinite(occurred_at))
    );

    CREATE INDEX user_role_audit_target_time_idx
      ON p32.user_role_audit
        (target_user_id, occurred_at DESC, audit_id DESC);

    REVOKE ALL ON TABLE p32.user_role_audit
      FROM PUBLIC, p32_app;

    GRANT SELECT ON TABLE p32.user_role_audit TO p32_app;
  `)
}

export function down(pgm) {
  // ย้อนกลับได้เมื่อยังไม่มีประวัติ เพื่อไม่ให้ลบ audit ที่บันทึกแล้วโดยเผลอ
  pgm.sql(`
    LOCK TABLE p32.user_role_audit IN ACCESS EXCLUSIVE MODE;

    DO $migration$
    BEGIN
      IF EXISTS (SELECT 1 FROM p32.user_role_audit) THEN
        RAISE EXCEPTION 'Refusing to drop non-empty user_role_audit';
      END IF;
    END;
    $migration$;

    DROP TABLE p32.user_role_audit RESTRICT;
  `)
}