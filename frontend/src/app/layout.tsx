import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import '../index.css'
import '../App.css'
import '../components/auth/LoginPage.css'
import '../components/auth/LoginForm.css'
import '../components/auth/LogoutButton.css'
import '../components/admin/RoleCatalog.css'
import '../components/admin/AdminUserLookup.css'

export const metadata: Metadata = {
  title: 'P32 | Project & Portfolio',
  description: 'ระบบบริหารและติดตามโครงงานนักศึกษา พร้อมแฟ้มสะสมผลงานดิจิทัล',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return <html lang="th"><body>{children}</body></html>
}
