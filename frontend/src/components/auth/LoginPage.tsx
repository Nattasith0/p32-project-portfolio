import AppIcon from '../ui/AppIcon'
import type { ReactNode } from 'react'
import type { IconName } from '../ui/AppIcon'

const features: { icon: IconName; title: string; description: string }[] = [
  {
    icon: 'reports',
    title: 'ติดตามโครงงาน',
    description: 'จัดการงานและความคืบหน้าของโครงงานอย่างเป็นระบบ',
  },
  {
    icon: 'portfolio',
    title: 'แฟ้มสะสมผลงาน',
    description: 'รวบรวมและแสดงผลงานในรูปแบบดิจิทัล (Portfolio)',
  },
  {
    icon: 'team',
    title: 'พื้นที่ทำงานร่วมกัน',
    description: 'เชื่อมการทำงานของนักศึกษาและอาจารย์ในพื้นที่เดียว',
  },
]

// จัดวางหน้าบัญชีเท่านั้น การตรวจตัวตนและส่งฟอร์มอยู่ใน component เดิม
export default function LoginPage({ children }: { children: ReactNode }) {
  return (
    <div className="login-page">
      <section className="login-intro" aria-labelledby="welcome-heading">
        <p className="login-intro__eyebrow">STUDENT PROJECT WORKSPACE</p>
        <h1 id="welcome-heading">ยินดีต้อนรับสู่ <span>P32</span></h1>
        <p className="login-intro__description">
          ระบบบริหารและติดตามโครงงานนักศึกษา
          พร้อมแฟ้มสะสมผลงานดิจิทัล
        </p>

        <ul className="login-features">
          {features.map((feature) => (
            <li className="login-feature" key={feature.icon}>
              <span className="login-feature__icon">
                <AppIcon name={feature.icon} />
              </span>
              <div>
                <h2>{feature.title}</h2>
                <p>{feature.description}</p>
              </div>
            </li>
          ))}
        </ul>

        <p className="login-intro__note">P32 · PROJECT &amp; PORTFOLIO</p>
      </section>

      <section className="login-card" aria-label="บัญชีผู้ใช้ P32">
        <div className="login-card__emblem">
          <AppIcon name="graduation" />
        </div>
        {children}
        <p className="login-card__footer">สำหรับผู้ใช้งานที่ได้รับบัญชี P32</p>
      </section>
    </div>
  )
}
