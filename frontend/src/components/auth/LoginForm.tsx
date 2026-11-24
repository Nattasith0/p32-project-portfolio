'use client'

import { useEffect, useRef, useState } from 'react'
import { AuthApiError, login } from '../../api/authApi'
import AppIcon from '../ui/AppIcon'
import type { FormEvent } from 'react'
import type { User } from '../../types/auth'

type LoginFormProps = { onSuccess: (user: User) => void }

function getLoginErrorMessage(error: unknown) {
    if (error instanceof AuthApiError) {
        if (error.status === 401) {
            return 'ชื่อบัญชีหรือรหัสผ่านไม่ถูกต้อง หรือบัญชียังไม่พร้อมใช้งาน'
        }

        if (error.status === 429) {
            return error.retryAfter
                ? `ส่งคำขอบ่อยเกินไป กรุณารออย่างน้อย ${error.retryAfter} วินาที แล้วลองใหม่`
                : 'ส่งคำขอบ่อยเกินไป กรุณารอสักครู่แล้วลองใหม่'
        }

        if (error.status === 403) {
            return 'ไม่สามารถยืนยันคำขอเข้าสู่ระบบได้ กรุณาลองใหม่'
        }
    }

    return 'ยังไม่สามารถเข้าสู่ระบบได้ กรุณาลองใหม่ภายหลัง'
}

export default function LoginForm({ onSuccess }: LoginFormProps) {
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [showPassword, setShowPassword] = useState(false)
    const [isSubmitting, setIsSubmitting] = useState(false)
    const [errorMessage, setErrorMessage] = useState('')
    const requestRef = useRef<AbortController | null>(null)

    useEffect(() => {
        return () => requestRef.current?.abort()
    }, [])

    async function handleSubmit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault()

        // กันส่งซ้ำทันที โดยไม่ต้องรอ React render รอบถัดไป
        if (requestRef.current !== null) return

        setErrorMessage('')

        const usernameLength = Array.from(username.trim()).length
        const passwordLength = Array.from(password).length

        if (usernameLength < 1 || usernameLength > 128) {
            setErrorMessage('กรุณากรอกชื่อบัญชี 1–128 ตัวอักษร')
            return
        }

        if (passwordLength < 1 || passwordLength > 1024) {
            setErrorMessage('กรุณากรอกรหัสผ่าน 1–1024 ตัวอักษร')
            return
        }

        const controller = new AbortController()
        requestRef.current = controller
        setIsSubmitting(true)

        let user: User | undefined

        try {
            user = await login({ username, password }, controller.signal)
        } catch (error) {
            if (!controller.signal.aborted) {
                setErrorMessage(getLoginErrorMessage(error))
            }
        } finally {
            if (requestRef.current === controller) {
                requestRef.current = null
            }

            if (!controller.signal.aborted) {
                setPassword('')
                setShowPassword(false)
                setIsSubmitting(false)
            }
        }

        if (user && !controller.signal.aborted) {
            onSuccess(user)
        }
    }

    return (
        <form
            className="login-form"
            onSubmit={handleSubmit}
            aria-labelledby="login-heading"
            aria-busy={isSubmitting}
        >
            <div className="login-form__heading">
                <h2 id="login-heading">เข้าสู่ระบบ P32</h2>
                <p>ใช้ชื่อบัญชีและรหัสผ่านที่ตั้งไว้สำหรับ P32</p>
            </div>

            <div className="login-form__field">
                <label htmlFor="login-username">ชื่อบัญชี</label>
                <div className="login-form__input-wrap">
                    <AppIcon name="user" className="login-form__input-icon" />
                    <input
                        id="login-username"
                        name="username"
                        type="text"
                        autoComplete="username"
                        autoCapitalize="none"
                        spellCheck={false}
                        placeholder="กรอกชื่อบัญชี P32"
                        value={username}
                        onChange={(event) => setUsername(event.target.value)}
                        aria-describedby={errorMessage ? 'login-error' : undefined}
                        disabled={isSubmitting}
                        required
                    />
                </div>
            </div>

            <div className="login-form__field">
                <label htmlFor="login-password">รหัสผ่าน</label>
                <div className="login-form__input-wrap login-form__input-wrap--password">
                    <AppIcon name="lock" className="login-form__input-icon" />
                    <input
                        id="login-password"
                        name="password"
                        type={showPassword ? 'text' : 'password'}
                        autoComplete="current-password"
                        placeholder="กรอกรหัสผ่าน"
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        aria-describedby={errorMessage ? 'login-error' : undefined}
                        disabled={isSubmitting}
                        required
                    />
                    <button
                        className="login-form__password-toggle"
                        type="button"
                        onClick={() => setShowPassword((visible) => !visible)}
                        aria-label={showPassword ? 'ซ่อนรหัสผ่าน' : 'แสดงรหัสผ่าน'}
                        aria-controls="login-password"
                        disabled={isSubmitting}
                    >
                        <AppIcon name={showPassword ? 'eyeOff' : 'eye'} />
                    </button>
                </div>
            </div>

            {errorMessage && <p id="login-error" role="alert">{errorMessage}</p>}

            <button className="login-form__submit" type="submit" disabled={isSubmitting}>
                {isSubmitting ? 'กำลังเข้าสู่ระบบ…' : 'เข้าสู่ระบบ'}
            </button>

            <p className="visually-hidden" role="status">
                {isSubmitting ? 'กำลังตรวจสอบบัญชี กรุณารอสักครู่' : ''}
            </p>
        </form>
    )
}
