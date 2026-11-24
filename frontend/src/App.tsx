'use client'

import { useEffect, useState } from 'react'
import { getCurrentUser } from './api/authApi'
import AppHeader from './components/layout/AppHeader'
import ApiStatus from './components/system/ApiStatus'
import SessionStatus from './components/auth/SessionStatus'
import LoginForm from './components/auth/LoginForm'
import LogoutButton from './components/auth/LogoutButton'
import LoginPage from './components/auth/LoginPage'
import type { SessionState, User } from './types/auth'

function App() {
  const [sessionState, setSessionState] = useState<SessionState>({
    status: 'loading',
    user: null,
  })

  useEffect(() => {
    const controller = new AbortController()

    async function loadCurrentUser() {
      try {
        const user = await getCurrentUser(controller.signal)

        if (!controller.signal.aborted) {
          setSessionState(user === null
            ? { status: 'unauthenticated', user: null }
            : { status: 'authenticated', user })
        }
      } catch {
        if (!controller.signal.aborted) {
          setSessionState({
            status: 'error',
            user: null,
          })
        }
      }
    }

    loadCurrentUser()

    return () => controller.abort()
  }, [])

  function handleLoginSuccess(user: User) {
    setSessionState({
      status: 'authenticated',
      user,
    })
  }

  function handleLogoutSuccess() {
    setSessionState({
      status: 'unauthenticated',
      user: null,
    })
  }

  const isAuthenticated = sessionState.status === 'authenticated'

  return (
    <div className={isAuthenticated ? 'app' : 'app app--login'}>
      <AppHeader />

      <main className={isAuthenticated ? 'app-main' : 'app-main app-main--login'}>
        {isAuthenticated ? (
          <section className="welcome-card">
            <p className="welcome-card__eyebrow">STUDENT PROJECT WORKSPACE</p>
            <h1>ยินดีต้อนรับสู่ P32</h1>
            <p className="welcome-card__description">
              ระบบบริหารและติดตามโครงงานนักศึกษา
              พร้อมแฟ้มสะสมผลงานดิจิทัล
            </p>
            <ApiStatus />
            <SessionStatus {...sessionState} />
            <LogoutButton onSuccess={handleLogoutSuccess} />
          </section>
        ) : (
          <LoginPage>
            {sessionState.status === 'unauthenticated' ? (
              <LoginForm onSuccess={handleLoginSuccess} />
            ) : (
              <div className="login-card__state">
                <h2>เข้าสู่ระบบ P32</h2>
                <SessionStatus {...sessionState} />
                {sessionState.status === 'error' && <a href="/">ตรวจสอบอีกครั้ง</a>}
              </div>
            )}
          </LoginPage>
        )}
      </main>
    </div>
  )
}

export default App
