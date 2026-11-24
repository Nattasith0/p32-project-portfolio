const icons = {
  graduation: <><path d="m2 9 10-5 10 5-10 5Z" /><path d="M6 11v6c4 3 8 3 12 0v-6M22 9v8" /></>,
  reports: <><rect x="5" y="5" width="14" height="16" rx="2" /><path d="M9 5V3h6v2M8 11l1 1 2-2M13 11h3M8 16l1 1 2-2M13 16h3" /></>,
  portfolio: <><path d="m3 7 9-5 9 5-9 5ZM3 12l9 5 9-5M3 17l9 5 9-5" /></>,
  team: <><circle cx="12" cy="7" r="3" /><path d="M6 21v-2a6 6 0 0 1 12 0v2M19 5a3 3 0 0 1 0 6M5 5a3 3 0 0 0 0 6M22 20v-2a5 5 0 0 0-3-4M2 20v-2a5 5 0 0 1 3-4" /></>,
  user: <><circle cx="12" cy="7" r="4" /><path d="M4 21v-2a8 8 0 0 1 16 0v2Z" /></>,
  lock: <><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" /></>,
  eye: <><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" /></>,
  eyeOff: <><path d="m3 3 18 18M10.6 5.1 12 5c6 0 10 7 10 7a18 18 0 0 1-3 3.5M6 6.5A22 22 0 0 0 2 12s4 7 10 7a12 12 0 0 0 5.5-1.5M10 10a3 3 0 0 0 4 4" /></>,
}

export type IconName = keyof typeof icons

type AppIconProps = { name: IconName; className?: string }

export default function AppIcon({ name, className = '' }: AppIconProps) {
  return (
    <svg
      className={className}
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {icons[name]}
    </svg>
  )
}
