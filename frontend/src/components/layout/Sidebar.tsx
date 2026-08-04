'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  LayoutDashboard, Radar, Target, Shield, ShieldAlert,
  FolderOpen, Clock, Bell, FileText, CheckSquare,
  Settings, ChevronRight, Zap, Eye,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { UserButton } from '@clerk/nextjs'

const NAV = [
  { label: 'Dashboard',    href: '/dashboard',            icon: LayoutDashboard },
  { label: 'Scans',        href: '/dashboard/scans',      icon: Radar },
  { label: 'Assets',       href: '/dashboard/assets',     icon: FolderOpen },
  { label: 'Findings',     href: '/dashboard/findings',   icon: Zap },
  { divider: true },
  { label: 'Kill Chain',   href: '/dashboard/killchain',  icon: Target },
  { label: 'OWASP Top 10', href: '/dashboard/owasp',      icon: ShieldAlert },
  { label: 'Compliance',   href: '/dashboard/compliance', icon: CheckSquare },
  { divider: true },
  { label: 'OSINT',        href: '/dashboard/osint',      icon: Eye },
  { label: 'Reports',      href: '/dashboard/reports',    icon: FileText },
  { label: 'Schedules',    href: '/dashboard/schedules',  icon: Clock },
  { label: 'Alerts',       href: '/dashboard/alerts',     icon: Bell },
  { divider: true },
  { label: 'Settings',     href: '/dashboard/settings',   icon: Settings },
]

export function Sidebar() {
  const pathname = usePathname()

  return (
    <aside
      className="flex w-60 flex-col border-r"
      style={{
        background: '#0C1628',
        borderColor: '#1E3A5F',
      }}
    >
      {/* Logo */}
      <div
        className="flex h-14 items-center gap-3 px-4"
        style={{ borderBottom: '1px solid #1E3A5F' }}
      >
        <div
          className="flex h-8 w-8 items-center justify-center rounded-lg"
          style={{ background: '#1D4ED8' }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z"
              fill="#EFF6FF"
              fillOpacity=".95"
            />
            <path
              d="M9 12l2 2 4-4"
              stroke="#1D4ED8"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        <div>
          <span
            className="text-sm font-bold tracking-widest"
            style={{ color: '#E2E8F0', letterSpacing: '0.1em' }}
          >
            BULWARK
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-2">
        {NAV.map((item, i) => {
          if ('divider' in item) {
            return (
              <div
                key={i}
                className="my-2"
                style={{ height: '1px', background: '#1E3A5F' }}
              />
            )
          }
          const Icon = item.icon
          const active =
            pathname === item.href ||
            (item.href !== '/dashboard' && pathname.startsWith(item.href))

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors',
              )}
              style={{
                background: active ? '#1D4ED820' : 'transparent',
                color: active ? '#60A5FA' : '#94A3B8',
                fontWeight: active ? 500 : 400,
              }}
              onMouseEnter={e => {
                if (!active) (e.currentTarget as HTMLElement).style.color = '#CBD5E1'
              }}
              onMouseLeave={e => {
                if (!active) (e.currentTarget as HTMLElement).style.color = '#94A3B8'
              }}
            >
              <Icon className="h-4 w-4 shrink-0" />
              <span className="flex-1">{item.label}</span>
              {active && (
                <ChevronRight className="h-3 w-3 opacity-50" />
              )}
            </Link>
          )
        })}
      </nav>

      {/* Tagline */}
      <div
        className="px-4 pb-2 pt-1"
        style={{ borderTop: '1px solid #1E293B' }}
      >
        <p
          className="text-center text-[10px] tracking-widest uppercase"
          style={{ color: '#334155' }}
        >
          Fortify · Detect · Defend
        </p>
      </div>

      {/* User */}
      <div className="p-3" style={{ borderTop: '1px solid #1E3A5F' }}>
        <div className="flex items-center gap-2.5 rounded-md px-2 py-1.5">
          <UserButton afterSignOutUrl="/sign-in" />
          <span className="text-xs" style={{ color: '#64748B' }}>Account</span>
        </div>
      </div>
    </aside>
  )
}
