export function up(pgm) {
  pgm.sql(`
    CREATE FUNCTION p32.change_user_role(
      p_actor_user_id UUID,
      p_target_user_id UUID,
      p_role_code TEXT,
      p_action TEXT,
      p_reason TEXT,
      p_request_id UUID
    )
    RETURNS TABLE (changed BOOLEAN, audit_id UUID)
    LANGUAGE plpgsql
    VOLATILE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $function$
    DECLARE
      v_target_active BOOLEAN;
      v_target_verified_at TIMESTAMPTZ;
      v_has_role BOOLEAN;
      v_audit_id UUID;
    BEGIN
      -- 1. ตรวจข้อมูลก่อนเปลี่ยนแปลงใด ๆ
      IF p_actor_user_id IS NULL OR p_target_user_id IS NULL
        OR p_request_id IS NULL OR p_role_code IS NULL
        OR char_length(p_role_code) NOT BETWEEN 1 AND 64
        OR p_action IS NULL OR p_action NOT IN ('assign', 'revoke')
        OR p_reason IS NULL OR p_reason <> btrim(p_reason)
        OR char_length(p_reason) NOT BETWEEN 1 AND 500
        OR p_reason !~ '[^[:space:]]'
      THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P3201', MESSAGE = 'ROLE_CHANGE_INVALID_INPUT';
      END IF;

      IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P3201', MESSAGE = 'ROLE_CHANGE_REQUIRES_READ_COMMITTED';
      END IF;

      -- 2. ใช้ transaction lock ร่วมกับ development seed; ไม่รอค้างเมื่อมีงานอื่น
      IF NOT pg_try_advisory_xact_lock(32, 1) THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P3207', MESSAGE = 'ROLE_CHANGE_BUSY';
      END IF;

      -- ล็อกบัญชีตามลำดับเดียวกัน และกันสถานะบัญชีเปลี่ยนระหว่างตรวจ/เขียน
      PERFORM u.user_id
      FROM p32.users AS u
      WHERE u.user_id IN (p_actor_user_id, p_target_user_id)
      ORDER BY u.user_id
      FOR SHARE;

      -- 3. actor มาจาก session ของ Backend; ตรวจสิทธิ์ปัจจุบันซ้ำในฐานข้อมูล
      IF NOT EXISTS (
        SELECT 1
        FROM p32.users AS u
        JOIN p32.user_roles AS ur ON ur.user_id = u.user_id
        WHERE u.user_id = p_actor_user_id
          AND u.is_active
          AND u.email_verified_at IS NOT NULL
          AND ur.role_code = 'system_admin'
      ) THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P3202', MESSAGE = 'ROLE_CHANGE_FORBIDDEN';
      END IF;

      SELECT u.is_active, u.email_verified_at
      INTO v_target_active, v_target_verified_at
      FROM p32.users AS u
      WHERE u.user_id = p_target_user_id;

      IF NOT FOUND THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P3203', MESSAGE = 'ROLE_TARGET_NOT_FOUND';
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM p32.roles AS r WHERE r.role_code = p_role_code
      ) THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P3204', MESSAGE = 'ROLE_NOT_FOUND';
      END IF;

      IF p_action = 'assign'
        AND (NOT v_target_active OR v_target_verified_at IS NULL)
      THEN
        RAISE EXCEPTION USING
          ERRCODE = 'P3205', MESSAGE = 'ROLE_TARGET_NOT_READY';
      END IF;

      SELECT EXISTS (
        SELECT 1 FROM p32.user_roles AS ur
        WHERE ur.user_id = p_target_user_id AND ur.role_code = p_role_code
      ) INTO v_has_role;

      -- เรียกซ้ำเพื่อให้ได้สถานะเดิม: ไม่เขียนบทบาทหรือ audit เพิ่ม
      IF (p_action = 'assign' AND v_has_role)
        OR (p_action = 'revoke' AND NOT v_has_role)
      THEN
        RETURN QUERY SELECT FALSE, NULL::UUID;
        RETURN;
      END IF;

      -- 4. เปลี่ยนบทบาท และป้องกันการถอนผู้ดูแลที่พร้อมใช้งานคนสุดท้าย
      IF p_action = 'assign' THEN
        INSERT INTO p32.user_roles (user_id, role_code, assigned_by)
        VALUES (p_target_user_id, p_role_code, p_actor_user_id);
      ELSE
        IF p_role_code = 'system_admin' THEN
          PERFORM u.user_id
          FROM p32.users AS u
          JOIN p32.user_roles AS ur ON ur.user_id = u.user_id
          WHERE ur.role_code = 'system_admin'
            AND u.user_id <> p_target_user_id
            AND u.is_active
            AND u.email_verified_at IS NOT NULL
          ORDER BY u.user_id
          FOR SHARE OF u;

          IF NOT FOUND THEN
            RAISE EXCEPTION USING
              ERRCODE = 'P3206', MESSAGE = 'LAST_SYSTEM_ADMIN';
          END IF;
        END IF;

        DELETE FROM p32.user_roles AS ur
        WHERE ur.user_id = p_target_user_id AND ur.role_code = p_role_code;
      END IF;

      -- 5. ถ้า audit ล้มเหลว PostgreSQL จะย้อนการเปลี่ยนบทบาทของคำสั่งนี้ด้วย
      INSERT INTO p32.user_role_audit AS a (
        target_user_id, role_code, action, actor_user_id, reason, request_id
      )
      VALUES (
        p_target_user_id, p_role_code, p_action,
        p_actor_user_id, p_reason, p_request_id
      )
      RETURNING a.audit_id INTO v_audit_id;

      RETURN QUERY SELECT TRUE, v_audit_id;
    END;
    $function$;

    REVOKE ALL ON FUNCTION p32.change_user_role(
      UUID, UUID, TEXT, TEXT, TEXT, UUID
    ) FROM PUBLIC, p32_app;

    GRANT EXECUTE ON FUNCTION p32.change_user_role(
      UUID, UUID, TEXT, TEXT, TEXT, UUID
    ) TO p32_app;
  `)
}

export function down(pgm) {
  pgm.sql(`
    DROP FUNCTION p32.change_user_role(
      UUID, UUID, TEXT, TEXT, TEXT, UUID
    ) RESTRICT;
  `)
}