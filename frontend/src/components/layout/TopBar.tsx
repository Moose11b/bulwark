'use client'

import { usePathname } from 'next/navigation'
import { Search, Shield } from 'lucide-react'

const PAGE_TITLES: Record<string, { title: string; sub: string }> = {
  '/dashboard':            { title: 'Dashboard',    sub: 'Security posture overview' },
  '/dashboard/scans':      { title: 'Scans',        sub: 'Active and historical scans' },
  '/dashboard/assets':     { title: 'Assets',       sub: 'Target inventory' },
  '/dashboard/findings':   { title: 'Findings',     sub: 'All vulnerability findings' },
  '/dashboard/killchain':  { title: 'Kill Chain',   sub: 'Lockheed Martin 7-phase mapping' },
  '/dashboard/owasp':      { title: 'OWASP Top 10', sub: 'OWASP 2021 category assessment' },
  '/dashboard/compliance': { title: 'Compliance',   sub: 'PCI-DSS · ISO 27001 · NIST CSF' },
  '/dashboard/osint':      { title: 'OSINT',        sub: 'Passive reconnaissance data' },
  '/dashboard/reports':    { title: 'Reports',      sub: 'PDF and structured exports' },
  '/dashboard/schedules':  { title: 'Schedules',    sub: 'Recurring scan automation' },
  '/dashboard/alerts':     { title: 'Alerts',       sub: 'Notification configuration' },
  '/dashboard/settings':   { title: 'Settings',     sub: 'Organisation and billing' },
}

export function TopBar() {
  const pathname = usePathname()
  const base = '/' + pathname.split('/').slice(1, 3).join('/')
  const meta = PAGE_TITLES[base] ?? { title: 'Bulwark', sub: '' }

  return (
    <header
      className="flex h-14 items-center justify-between px-6"
      style={{
        background: '#0C1628',
        borderBottom: '1px solid #1E3A5F',
      }}
    >
      <div>
        <h1 className="text-sm font-semibold" style={{ color: '#E2E8F0' }}>
          {meta.title}
        </h1>
        {meta.sub && (
          <p className="text-xs" style={{ color: '#64748B' }}>
            {meta.sub}
          </p>
        )}
      </div>

      <div className="flex items-center gap-3">
        {/* Search */}
        <div
          className="flex items-center gap-2 rounded-md px-3 py-1.5"
          style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}
        >
          <Search className="h-3.5 w-3.5" style={{ color: '#64748B' }} />
          <input
            placeholder="Search findings..."
            className="w-36 bg-transparent text-xs outline-none placeholder:text-[#475569]"
            style={{ color: '#E2E8F0' }}
          />
          <kbd
            className="rounded px-1 text-[10px]"
            style={{ background: '#0F172A', color: '#475569', border: '0.5px solid #1E3A5F' }}
          >
            ⌘K
          </kbd>
        </div>

        {/* Shield status indicator */}
        <div
          className="flex items-center gap-1.5 rounded-md px-2.5 py-1.5"
          style={{ background: '#14532D22', border: '0.5px solid #14532D55' }}
        >
          <Shield className="h-3.5 w-3.5" style={{ color: '#86EFAC' }} />
          <span className="text-xs font-medium" style={{ color: '#86EFAC' }}>
            Defended
          </span>
        </div>
      </div>
    </header>
  )
}
