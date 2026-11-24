import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { isRoleChangeReason, type RoleChangeAction } from '../../api/roleChangeApi'
import type { AdminUserRoles } from '../../types/adminUsers'
import type { RoleDefinition } from '../../types/roles'

type Props = {
  account: AdminUserRoles
  catalog: RoleDefinition[]
  busy: boolean
  onConfirm: (action: RoleChangeAction, roleCode: string, reason: string) => void
}

export default function RoleChangeForm({ account, catalog, busy, onConfirm }: Props) {
  const id = useId()
  const [action, setAction] = useState<RoleChangeAction>('assign')
  const [roleCode, setRoleCode] = useState('')
  const [reason, setReason] = useState('')
  const [review, setReview] = useState(false)
  const [validationError, setValidationError] = useState('')
  const reviewTitle = useRef<HTMLHeadingElement>(null)
  const roleSelect = useRef<HTMLSelectElement>(null)

  const assigned = new Set(account.roles.map((role) => role.roleCode))
  const choices = action === 'revoke'
    ? account.roles
    : account.user.isActive && account.user.emailVerified
      ? catalog.filter((role) => !assigned.has(role.roleCode))
      : []
  const role = choices.find((choice) => choice.roleCode === roleCode)
  const actionLabel = action === 'assign' ? 'มอบหมาย' : 'ถอน'

  useEffect(() => {
    if (review) reviewTitle.current?.focus()
  }, [review])

  function reviewChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    if (!role || !isRoleChangeReason(reason)) {
      setValidationError('กรุณาเลือกบทบาทและระบุเหตุผล 1–500 ตัวอักษร')
      return
    }
    setValidationError('')
    setReview(true)
  }

  return (
    <div className="role-change-form">
      {review && role ? (
        <>
          <h4 ref={reviewTitle} tabIndex={-1}>ยืนยันการเปลี่ยนบทบาท</h4>
          <p>{actionLabel}บทบาท <strong>{role.roleName}</strong> ให้บัญชี <strong>{account.user.username}</strong></p>
          <p>เหตุผล: {reason.trim()}</p>
          <div className="role-change-form__actions">
            <button className="role-catalog__reload" type="button" disabled={busy}
              onClick={() => onConfirm(action, role.roleCode, reason)}>
              {busy ? 'กำลังบันทึก…' : `ยืนยัน${actionLabel}บทบาท`}
            </button>
            <button className="role-catalog__reload" type="button" disabled={busy}
              onClick={() => {
                setReview(false)
                requestAnimationFrame(() => roleSelect.current?.focus())
              }}>
              กลับไปแก้ไข
            </button>
          </div>
        </>
      ) : (
        <form onSubmit={reviewChange}>
          <h4>เปลี่ยนบทบาท</h4>
          <fieldset disabled={busy}>
            <label htmlFor={`${id}-action`}>การดำเนินการ</label>
            <select id={`${id}-action`} value={action} onChange={(event) => {
              setAction(event.target.value === 'revoke' ? 'revoke' : 'assign')
              setRoleCode('')
              setValidationError('')
            }}>
              <option value="assign">มอบหมายบทบาท</option>
              <option value="revoke">ถอนบทบาท</option>
            </select>
            <label htmlFor={`${id}-role`}>บทบาท</label>
            <select ref={roleSelect} id={`${id}-role`} value={roleCode} disabled={choices.length === 0}
              onChange={(event) => { setRoleCode(event.target.value); setValidationError('') }}>
              <option value="">เลือกบทบาท</option>
              {choices.map((choice) => <option key={choice.roleCode} value={choice.roleCode}>{choice.roleName}</option>)}
            </select>
            {choices.length === 0 && <p>ไม่มีบทบาทให้{actionLabel}สำหรับบัญชีนี้</p>}
            <label htmlFor={`${id}-reason`}>เหตุผล (1–500 ตัวอักษร)</label>
            <textarea id={`${id}-reason`} value={reason} rows={3}
              onChange={(event) => { setReason(event.target.value); setValidationError('') }} />
            {validationError && <p role="alert">{validationError}</p>}
            <button className="role-catalog__reload" type="submit" disabled={choices.length === 0}>
              ตรวจสอบก่อนบันทึก
            </button>
          </fieldset>
        </form>
      )}
    </div>
  )
}
