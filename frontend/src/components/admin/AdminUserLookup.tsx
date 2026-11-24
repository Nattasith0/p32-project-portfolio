'use client'

import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { AdminUsersApiError, getAdminUserRoles, searchAdminUsers } from '../../api/adminUsersApi'
import type { AdminUser, AdminUserRoles, AdminUserSearchPage } from '../../types/adminUsers'
import type { RoleDefinition } from '../../types/roles'
import { changeUserRole, RoleChangeApiError, type RoleChangeAction } from '../../api/roleChangeApi'
import RoleChangeForm from './RoleChangeForm'

type AccessLost = 'unauthenticated' | 'forbidden'
type RequestError = { message: string; requestId: string | null }
type Search = AdminUserSearchPage & { query: string; pending: boolean; error: RequestError | null }
type Selection =
  | { status: 'loading'; user: AdminUser }
  | ({ status: 'ready' } & AdminUserRoles)
  | { status: 'error'; user: AdminUser; error: RequestError }

const ROLE_CHANGE_MESSAGES = new Map([
  ['CSRF_INVALID', 'ยืนยันความปลอดภัยของคำขอไม่สำเร็จ กรุณาตรวจสอบบทบาทแล้วลองอีกครั้ง'],
  ['ORIGIN_NOT_ALLOWED', 'ระบบปฏิเสธแหล่งที่มาของคำขอ'],
  ['ROLE_CHANGE_BUSY', 'มีการเปลี่ยนบทบาทพร้อมกัน กรุณาตรวจสอบบทบาทแล้วลองอีกครั้ง'],
  ['LAST_SYSTEM_ADMIN', 'ระบบต้องมีผู้ดูแลที่ใช้งานได้อย่างน้อยหนึ่งบัญชี'],
  ['ROLE_TARGET_NOT_READY', 'บัญชียังไม่พร้อมรับบทบาท'],
  ['ROLE_TARGET_NOT_FOUND', 'ไม่พบบัญชีที่เลือก'],
  ['ROLE_NOT_FOUND', 'ไม่พบบทบาทที่เลือก กรุณาโหลดรายการบทบาทใหม่'],
  ['INVALID_ROLE_CHANGE_INPUT', 'กรุณาตรวจสอบบทบาทและเหตุผลอีกครั้ง'],
])

type ChangeNotice = { message: string; auditId: string | null } | { error: RequestError }

function RequestMessage({ error }: { error: RequestError }) {
  return (
    <div role="alert">
      <p>{error.message}</p>
      {error.requestId && (
        <p className="role-catalog__reference">รหัสอ้างอิง: <code>{error.requestId}</code></p>
      )}
    </div>
  )
}

export default function AdminUserLookup({ catalog, busy, onBusyChange, onAccessLost }: {
  catalog: RoleDefinition[]
  busy: boolean
  onBusyChange: (busy: boolean) => void
  onAccessLost: (status: AccessLost) => void
}) {
  const id = useId()
  const [draft, setDraft] = useState('')
  const [inputError, setInputError] = useState('')
  const [changeNotice, setChangeNotice] = useState<ChangeNotice | null>(null)
  const changingRole = useRef(false)
  const [search, setSearch] = useState<Search | null>(null)
  const [selection, setSelection] = useState<Selection | null>(null)
  const searchRequest = useRef<AbortController | null>(null)
  const rolesRequest = useRef<AbortController | null>(null)

  useEffect(() => () => {
    searchRequest.current?.abort()
    rolesRequest.current?.abort()
  }, [])

  function handleAccessLoss(error: unknown) {
    const isReadDenial = error instanceof AdminUsersApiError && error.status === 403
    const isWriteDenial = error instanceof RoleChangeApiError && error.status === 403 && error.code === 'FORBIDDEN'
    const isSignedOut = (error instanceof AdminUsersApiError || error instanceof RoleChangeApiError) && error.status === 401
    if (!isReadDenial && !isWriteDenial && !isSignedOut) {
      return false
    }

    searchRequest.current?.abort()
    rolesRequest.current?.abort()
    onAccessLost(isSignedOut ? 'unauthenticated' : 'forbidden')
    return true
  }

  async function loadPage(query: string, previous?: Search) {
    searchRequest.current?.abort()
    const controller = new AbortController()
    searchRequest.current = controller

    const users = previous?.users ?? []
    const after = previous?.nextCursor ?? null
    const pending = { query, users, nextCursor: after, pending: true, error: null }
    setSearch(pending)

    try {
      const page = await searchAdminUsers({ q: query, after }, controller.signal)
      if (controller.signal.aborted) return
      setSearch({ ...pending, users: [...users, ...page.users], nextCursor: page.nextCursor, pending: false })
    } catch (error) {
      if (controller.signal.aborted || handleAccessLoss(error)) return
      setSearch({
        ...pending,
        pending: false,
        error: {
          message: 'ค้นหาบัญชีไม่สำเร็จ กรุณาลองอีกครั้ง',
          requestId: error instanceof AdminUsersApiError ? error.requestId : null,
        },
      })
    }
  }

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (changingRole.current) return
    const query = draft.trim()
    const length = Array.from(query).length
    if (length < 2 || length > 100 || !/[^\p{White_Space}\uFEFF]/u.test(query)) {
      setInputError('กรุณากรอกคำค้น 2–100 ตัวอักษร')
      return
    }

    setInputError('')
    rolesRequest.current?.abort()
    setSelection(null)
    setChangeNotice(null)
    void loadPage(query)
  }

  async function selectUser(user: AdminUser) {
    rolesRequest.current?.abort()
    const controller = new AbortController()
    rolesRequest.current = controller
    setSelection({ status: 'loading', user })

    try {
      const result = await getAdminUserRoles(user.userId, controller.signal)
      if (!controller.signal.aborted) setSelection({ status: 'ready', ...result })
    } catch (error) {
      if (controller.signal.aborted || handleAccessLoss(error)) return
      const apiError = error instanceof AdminUsersApiError ? error : null
      setSelection({
        status: 'error',
        user,
        error: {
          message: apiError?.status === 404
            ? 'ไม่พบบัญชีนี้แล้ว กรุณาค้นหาบัญชีใหม่'
            : 'โหลดบทบาทของบัญชีไม่สำเร็จ กรุณาเลือกบัญชีอีกครั้ง',
          requestId: apiError?.requestId ?? null,
        },
      })
    }
  }

  async function submitRoleChange(action: RoleChangeAction, roleCode: string, reason: string) {
    if (changingRole.current || search?.pending || selection?.status !== 'ready') return
    const user = selection.user
    changingRole.current = true
    onBusyChange(true)
    setChangeNotice(null)

    try {
      try {
        const result = await changeUserRole({ targetUserId: user.userId, action, roleCode, reason })
        setChangeNotice({
          message: result.changed ? 'บันทึกการเปลี่ยนบทบาทแล้ว' : 'บัญชีมีสถานะบทบาทตามคำขออยู่แล้ว',
          auditId: result.auditId,
        })
      } catch (error) {
        if (handleAccessLoss(error)) return
        const apiError = error instanceof RoleChangeApiError ? error : null
        setChangeNotice({
          error: {
            message: (apiError && ROLE_CHANGE_MESSAGES.get(apiError.code)) ??
              'ยืนยันผลการบันทึกไม่ได้ ระบบจะโหลดบทบาทปัจจุบันใหม่ โปรดตรวจสอบก่อนส่งอีกครั้ง',
            requestId: apiError?.requestId ?? null,
          },
        })
      }

      // อ่านสถานะจริงซ้ำหลังบันทึก รวมถึงกรณีที่การตอบกลับขาดหาย
      await selectUser(user)
    } finally {
      changingRole.current = false
      onBusyChange(false)
    }
  }

  return (
    <section className="admin-user-lookup" aria-labelledby={`${id}-heading`}>
      <h2 id={`${id}-heading`}>ค้นหาบัญชีผู้ใช้</h2>
      <form onSubmit={submitSearch}>
        <label htmlFor={`${id}-query`}>ชื่อบัญชีหรือชื่อที่แสดง</label>
        <div className="admin-user-lookup__search">
          <input
            id={`${id}-query`}
            type="search"
            disabled={busy}
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value)
              setInputError('')
            }}
            aria-invalid={Boolean(inputError)}
            aria-describedby={`${id}-help${inputError ? ` ${id}-error` : ''}`}
          />
          <button className="role-catalog__reload" type="submit" disabled={busy}>ค้นหา</button>
        </div>
        <p id={`${id}-help`} className="admin-user-lookup__hint">กรอกคำค้น 2–100 ตัวอักษร</p>
        {inputError && <p id={`${id}-error`} role="alert">{inputError}</p>}
      </form>

      {search && (
        <div className="admin-user-lookup__columns">
          <section aria-labelledby={`${id}-results`}>
            <h3 id={`${id}-results`}>ผลค้นหา “{search.query}”</h3>
            <p role="status">
              {search.pending
                ? 'กำลังค้นหาบัญชี…'
                : search.users.length > 0
                  ? `แสดง ${search.users.length} บัญชี`
                  : !search.error && 'ไม่พบบัญชีที่ตรงกับคำค้น'}
            </p>
            {search.error && <RequestMessage error={search.error} />}
            {search.users.length > 0 && (
              <ul className="admin-user-lookup__results">
                {search.users.map((user) => (
                  <li key={user.userId}>
                    <button
                      type="button"
                      aria-current={selection?.user.userId === user.userId ? 'true' : undefined}
                      disabled={busy}
                      onClick={() => {
                        setChangeNotice(null)
                        void selectUser(user)
                      }}
                    >
                      <strong>{user.displayName}</strong>
                      <span>{user.username}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
            {search.nextCursor && (
              <button
                type="button"
                className="role-catalog__reload"
                disabled={search.pending || busy}
                onClick={() => void loadPage(search.query, search)}
              >
                โหลดบัญชีเพิ่มเติม
              </button>
            )}
          </section>

          <section className="admin-user-lookup__detail" aria-labelledby={`${id}-roles`}>
            <h3 id={`${id}-roles`}>บทบาทปัจจุบัน</h3>
            {!selection && <p>เลือกบัญชีจากผลค้นหาเพื่อดูบทบาท</p>}
            {selection && <p><strong>{selection.user.displayName}</strong> · {selection.user.username}</p>}
            {changeNotice && ('error' in changeNotice ? (
              <RequestMessage error={changeNotice.error} />
            ) : (
              <div role="status">
                <p>{changeNotice.message}</p>
                {changeNotice.auditId && (
                  <p className="role-catalog__reference">
                    รหัสประวัติ: <code>{changeNotice.auditId}</code>
                  </p>
                )}
              </div>
            ))}
            {selection?.status === 'loading' && <p role="status">กำลังโหลดบทบาท…</p>}
            {selection?.status === 'error' && <RequestMessage error={selection.error} />}
            {selection?.status === 'ready' && (
              <>
                <p>{selection.user.isActive ? 'บัญชีเปิดใช้งาน' : 'บัญชีปิดใช้งาน'}</p>
                <p>{selection.user.emailVerified ? 'ยืนยันอีเมลแล้ว' : 'ยังไม่ได้ยืนยันอีเมล'}</p>
                <p role="status">
                  {selection.roles.length === 0 ? 'บัญชีนี้ยังไม่มีบทบาท' : `พบ ${selection.roles.length} บทบาท`}
                </p>
                {selection.roles.length > 0 && (
                  <ul>{selection.roles.map((role) => <li key={role.roleCode}>{role.roleName}</li>)}</ul>
                )}
                <RoleChangeForm account={selection} catalog={catalog} busy={busy || search.pending}
                  onConfirm={(action, roleCode, reason) => void submitRoleChange(action, roleCode, reason)} />
              </>
            )}
          </section>
        </div>
      )}
    </section>
  )
}
