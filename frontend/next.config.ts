import type { NextConfig } from 'next'

// ค่าฝั่ง server เท่านั้น ห้ามเปลี่ยนเป็น NEXT_PUBLIC_* หรือใส่กุญแจ Backend
const apiOrigin = process.env.P32_API_ORIGIN ?? 'http://127.0.0.1:3001'
const target = new URL(apiOrigin)
if (!['http:', 'https:'].includes(target.protocol) || target.origin !== apiOrigin) {
  throw new Error('P32_API_ORIGIN must be a canonical HTTP(S) origin')
}

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  async rewrites() {
    return [{ source: '/api/:path*', destination: `${apiOrigin}/api/:path*` }]
  },
}

export default nextConfig
