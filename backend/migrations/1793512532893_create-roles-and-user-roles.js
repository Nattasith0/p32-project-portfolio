export function up(pgm) {
    pgm.sql(`
    CREATE TABLE p32.roles (
      role_code TEXT PRIMARY KEY,
      role_name TEXT NOT NULL,

      CONSTRAINT roles_code_normalized
        CHECK (
          role_code = lower(btrim(role_code))
          AND role_code <> ''
        ),

      CONSTRAINT roles_name_not_blank
        CHECK (btrim(role_name) <> '')
    );

    CREATE TABLE p32.user_roles (
      user_id UUID NOT NULL,
      role_code TEXT NOT NULL,
      assigned_by UUID NOT NULL,
      assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),

      CONSTRAINT user_roles_pkey
        PRIMARY KEY (user_id, role_code),

      CONSTRAINT user_roles_user_fk
        FOREIGN KEY (user_id)
        REFERENCES p32.users (user_id)
        ON DELETE RESTRICT,

      CONSTRAINT user_roles_role_fk
        FOREIGN KEY (role_code)
        REFERENCES p32.roles (role_code)
        ON DELETE RESTRICT,

      CONSTRAINT user_roles_assigned_by_fk
        FOREIGN KEY (assigned_by)
        REFERENCES p32.users (user_id)
        ON DELETE RESTRICT
    );

    INSERT INTO p32.roles (role_code, role_name)
    VALUES
      ('student', 'นักศึกษาในโครงงาน'),
      ('advisor', 'อาจารย์ที่ปรึกษา'),
      ('course_manager', 'ผู้ดูแลวิชา'),
      ('examiner', 'กรรมการสอบ'),
      ('portfolio_viewer', 'นักศึกษาผู้ชม Portfolio ภายใน'),
      ('system_admin', 'ผู้ดูแลระบบ');

    REVOKE ALL ON TABLE
      p32.roles,
      p32.user_roles
    FROM PUBLIC;

    GRANT SELECT ON TABLE
      p32.roles,
      p32.user_roles
    TO p32_app;
  `)
}

export function down(pgm) {
    pgm.sql(`
    DROP TABLE p32.user_roles RESTRICT;
    DROP TABLE p32.roles RESTRICT;
  `)
}