'use client'

import { useEffect, useRef, useState } from 'react'
import { logout } from '../../api/authApi'
type LogoutButtonProps = { onSuccess: () => void }

export default function LogoutButton({ onSuccess }: LogoutButtonProps) {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [errorMessage, setErrorMessage] = useState('')
  const requestRef = useRef<AbortController | null>(null)

  useEffect(() => {
    return () => requestRef.current?.abort()
  }, [])

  async function handleLogout() {
    if (requestRef.current !== null) return

    const controller = new AbortController()
    requestRef.current = controller
    setErrorMessage('')
    setIsSubmitting(true)

    try {
      await logout(controller.signal)
    } catch {
      if (!controller.signal.aborted) {
        setErrorMessage('ยังยืนยันการออกจากระบบไม่ได้ กรุณาลองใหม่')
      }
      return
    } finally {
      if (requestRef.current === controller) {
        requestRef.current = null
      }

      if (!controller.signal.aborted) {
        setIsSubmitting(false)
      }
    }

    if (!controller.signal.aborted) {
      onSuccess()
    }
  }

  return (
    <div className="logout-actions" aria-busy={isSubmitting}>
      <button
        type="button"
        onClick={handleLogout}
        disabled={isSubmitting}
      >
        {isSubmitting ? 'กำลังออกจากระบบ…' : 'ออกจากระบบ'}
      </button>

      <p role="status">
        {isSubmitting ? 'กำลังดำเนินการ กรุณารอสักครู่' : ''}
      </p>

      {errorMessage && <p role="alert">{errorMessage}</p>}
    </div>
  )
}