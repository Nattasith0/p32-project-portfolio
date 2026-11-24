import type { Metadata } from 'next'
import AppHeader from '../../../components/layout/AppHeader'
import RoleCatalog from '../../../components/admin/RoleCatalog'

export const metadata: Metadata = { title: 'รายการบทบาท | P32' }

export default function RolesPage() {
  return (
    <div className="app">
      <AppHeader />
      <main className="app-main">
        <nav className="role-catalog-page__navigation" aria-label="ตำแหน่งปัจจุบัน">
          <a href="/">หน้าหลัก</a>
          <span aria-hidden="true">/</span>
          <span aria-current="page">รายการบทบาท</span>
        </nav>
        <RoleCatalog />
      </main>
    </div>
  )
}
