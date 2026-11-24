'use client'

import { useEffect, useId, useState } from 'react'
import { getRoleCatalog, RoleCatalogApiError } from '../../api/rolesApi'
import type { RoleDefinition } from '../../types/roles'
import AdminUserLookup from './AdminUserLookup'

type CatalogState =
  | { status: 'loading' }
  | { status: 'ready'; roles: RoleDefinition[] }
  | { status: 'unauthenticated' }
  | { status: 'forbidden' }
  | { status: 'error'; requestId: string | null }

export default function RoleCatalog() {
  const titleId = useId()
  const [state, setState] = useState<CatalogState>({ status: 'loading' })
  const [attempt, setAttempt] = useState(0)
  const [changingRole, setChangingRole] = useState(false)

  useEffect(() => {
    const controller = new AbortController()

    async function loadRoles() {
      try {
        const roles = await getRoleCatalog(controller.signal)
        if (!controller.signal.aborted) setState({ status: 'ready', roles })
      } catch (error) {
        if (controller.signal.aborted) return

        if (error instanceof RoleCatalogApiError && error.status === 401) {
          setState({ status: 'unauthenticated' })
        } else if (error instanceof RoleCatalogApiError && error.status === 403) {
          setState({ status: 'forbidden' })
        } else {
          setState({
            status: 'error',
            requestId: error instanceof RoleCatalogApiError ? error.requestId : null,
          })
        }
      }
    }

    void loadRoles()
    return () => controller.abort()
  }, [attempt])

  function reloadRoles() {
    // ล้างรายการเดิมทันทีเมื่อเริ่มตรวจสิทธิ์และโหลดใหม่
    setState({ status: 'loading' })
    setAttempt((value) => value + 1)
  }

  return (
    <section className="role-catalog" aria-labelledby={titleId}>
      <header className="role-catalog__header">
        <div>
          <p className="role-catalog__eyebrow">จัดการสิทธิ์</p>
          <h1 id={titleId}>รายการบทบาทของระบบ</h1>
        </div>
        <button
          className="role-catalog__reload"
          type="button"
          onClick={reloadRoles}
          disabled={state.status === 'loading' || changingRole}
        >
          โหลดรายการใหม่
        </button>
      </header>

      <p className="role-catalog__description">
        บทบาทที่ระบบรองรับสำหรับการมอบหมายสิทธิ์ให้บัญชีผู้ใช้
      </p>

      <div className="role-catalog__content">
        {state.status === 'loading' && (
          <p className="role-catalog__message" role="status">
            กำลังโหลดรายการบทบาท…
          </p>
        )}

        {state.status === 'unauthenticated' && (
          <div className="role-catalog__message" role="status">
            <h2>กรุณาเข้าสู่ระบบ</h2>
            <p>เข้าสู่ระบบเพื่อให้ระบบตรวจสอบสิทธิ์การเข้าถึงหน้านี้</p>
            <a className="role-catalog__link" href="/">
              เข้าสู่ระบบ
            </a>
          </div>
        )}

        {state.status === 'forbidden' && (
          <div className="role-catalog__message" role="status">
            <h2>ไม่มีสิทธิ์เข้าถึงหน้านี้</h2>
            <p>รายการบทบาทส่วนนี้เปิดให้ผู้ดูแลระบบเข้าถึง</p>
            <a className="role-catalog__link" href="/">
              กลับหน้าหลัก
            </a>
          </div>
        )}

        {state.status === 'error' && (
          <div className="role-catalog__message" role="alert">
            <h2>โหลดรายการบทบาทไม่สำเร็จ</h2>
            <p>กรุณาตรวจสอบการเชื่อมต่อ แล้วกดโหลดรายการใหม่อีกครั้ง</p>
            {state.requestId && (
              <p className="role-catalog__reference">
                รหัสอ้างอิง: <code>{state.requestId}</code>
              </p>
            )}
          </div>
        )}

        {state.status === 'ready' &&
          (state.roles.length === 0 ? (
            <p className="role-catalog__message" role="status">
              ยังไม่มีรายการบทบาท
            </p>
          ) : (
            <>
              <p className="role-catalog__count" role="status">
                พบ {state.roles.length} บทบาท
              </p>
              <table className="role-catalog__table">
                <caption className="visually-hidden">รายชื่อบทบาทที่ระบบรองรับ</caption>
                <thead>
                  <tr>
                    <th scope="col">ลำดับ</th>
                    <th scope="col">ชื่อบทบาท</th>
                  </tr>
                </thead>
                <tbody>
                  {state.roles.map((role, index) => (
                    <tr key={role.roleCode}>
                      <td>{index + 1}</td>
                      <td>{role.roleName}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ))}
      </div>
      {state.status === 'ready' && (
        <AdminUserLookup catalog={state.roles} busy={changingRole} onBusyChange={setChangingRole}
          onAccessLost={(status) => setState({ status })} />
      )}
    </section>
  )
}
