'use client'

import { useQuery } from '@tanstack/react-query'
import Link from 'next/link'
import { api } from '@/lib/api'
import {
  Shield, Radar, AlertTriangle, TrendingUp,
  ChevronRight, Plus, Clock, Zap,
} from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip,
  ResponsiveContainer, BarChart, Bar, Cell,
} from 'recharts'

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#FCA5A5',
  HIGH:     '#FDBA74',
  MEDIUM:   '#FDE68A',
  LOW:      '#86EFAC',
  INFO:     '#93C5FD',
}

const SEV_BG: Record<string, string> = {
  CRITICAL: '#7F1D1D33',
  HIGH:     '#7C2D1233',
  MEDIUM:   '#71360233',
  LOW:      '#14532D33',
  INFO:     '#1E3A5F33',
}

function StatCard({
  label, value, sub, color, icon: Icon,
}: {
  label: string; value: string | number; sub?: string
  color: string; icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>
}) {
  return (
    <div
      className="rounded-lg p-5 flex items-start justify-between"
      style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}
    >
      <div>
        <p className="text-xs font-medium mb-1" style={{ color: '#64748B' }}>{label}</p>
        <p className="text-3xl font-bold" style={{ color }}>{value}</p>
        {sub && <p className="text-xs mt-1" style={{ color: '#475569' }}>{sub}</p>}
      </div>
      <div className="rounded-lg p-2" style={{ background: `${color}15` }}>
        <Icon className="h-5 w-5" style={{ color }} />
      </div>
    </div>
  )
}

function ScanRow({ scan }: { scan: any }) {
  const statusColor = {
    completed: '#86EFAC', running: '#60A5FA',
    failed: '#FCA5A5', queued: '#FDE68A', cancelled: '#94A3B8',
  }[scan.status as string] ?? '#94A3B8'

  return (
    <Link
      href={`/dashboard/scans/${scan.id}`}
      className="flex items-center justify-between rounded-lg px-4 py-3 transition-colors"
      style={{ background: '#0F172A', border: '0.5px solid #1E3A5F' }}
    >
      <div className="flex items-center gap-3 min-w-0">
        <div
          className="h-2 w-2 rounded-full shrink-0"
          style={{ background: statusColor }}
        />
        <div className="min-w-0">
          <p className="text-sm font-medium truncate" style={{ color: '#E2E8F0' }}>
            {scan.target}
          </p>
          <p className="text-xs" style={{ color: '#475569' }}>
            {scan.scan_type?.toUpperCase()} · {new Date(scan.created_at).toLocaleDateString()}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-3 shrink-0 ml-3">
        {scan.status === 'completed' && (
          <div className="text-right">
            <p className="text-sm font-bold" style={{
              color: scan.risk_score > 60 ? '#FCA5A5' : scan.risk_score > 30 ? '#FDBA74' : '#86EFAC'
            }}>
              {scan.risk_score?.toFixed(0)}
            </p>
            <p className="text-xs" style={{ color: '#475569' }}>risk</p>
          </div>
        )}
        <ChevronRight className="h-4 w-4" style={{ color: '#334155' }} />
      </div>
    </Link>
  )
}

function FindingRow({ finding }: { finding: any }) {
  const sev = finding.severity ?? 'INFO'
  return (
    <div
      className="flex items-center justify-between rounded-lg px-4 py-3"
      style={{ background: '#0F172A', border: '0.5px solid #1E3A5F' }}
    >
      <div className="flex items-center gap-3 min-w-0">
        <span
          className="text-xs font-medium px-2 py-0.5 rounded-full shrink-0"
          style={{ background: SEV_BG[sev], color: SEV_COLOR[sev] }}
        >
          {sev}
        </span>
        <p className="text-sm truncate" style={{ color: '#CBD5E1' }}>
          {finding.title}
        </p>
      </div>
      <p className="text-xs shrink-0 ml-3" style={{ color: '#475569' }}>
        {finding.source}
      </p>
    </div>
  )
}

export default function DashboardPage() {
  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ['scans-recent'],
    queryFn: () => api.get('/api/scans?limit=8').then(r => r.data),
  })

  const { data: findings } = useQuery({
    queryKey: ['findings-critical'],
    queryFn: () => api.get('/api/findings?severity=CRITICAL&limit=5').then(r => r.data),
  })

  const completedScans = (scans ?? []).filter((s: any) => s.status === 'completed')
  const runningScans = (scans ?? []).filter((s: any) => s.status === 'running')
  const avgRisk = completedScans.length
    ? Math.round(completedScans.reduce((a: number, s: any) => a + (s.risk_score ?? 0), 0) / completedScans.length)
    : 0

  const trendData = completedScans.slice(-7).map((s: any) => ({
    date: new Date(s.created_at).toLocaleDateString('en', { month: 'short', day: 'numeric' }),
    risk: Math.round(s.risk_score ?? 0),
  }))

  return (
    <div className="space-y-6 animate-fade-in">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: '#E2E8F0' }}>
            Security posture
          </h1>
          <p className="text-sm mt-0.5" style={{ color: '#64748B' }}>
            {completedScans.length} completed scans
            {runningScans.length > 0 && ` · ${runningScans.length} running`}
          </p>
        </div>
        <Link
          href="/dashboard/scans/new"
          className="flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors"
          style={{ background: '#1D4ED8', color: '#EFF6FF' }}
        >
          <Plus className="h-4 w-4" />
          New scan
        </Link>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Average risk score"
          value={avgRisk}
          sub="across all scans"
          color={avgRisk > 60 ? '#FCA5A5' : avgRisk > 30 ? '#FDBA74' : '#86EFAC'}
          icon={Shield}
        />
        <StatCard
          label="Total scans"
          value={(scans ?? []).length}
          sub="all time"
          color="#60A5FA"
          icon={Radar}
        />
        <StatCard
          label="Critical findings"
          value={findings?.length ?? 0}
          sub="requiring attention"
          color="#FCA5A5"
          icon={AlertTriangle}
        />
        <StatCard
          label="Active scans"
          value={runningScans.length}
          sub="currently running"
          color="#F59E0B"
          icon={Zap}
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">

        {/* Risk trend */}
        <div
          className="col-span-2 rounded-lg p-5"
          style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}
        >
          <p className="text-sm font-medium mb-4" style={{ color: '#E2E8F0' }}>
            Risk score trend
          </p>
          {trendData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#1D4ED8" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#1D4ED8" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fill: '#475569', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fill: '#475569', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: '#0F172A', border: '1px solid #1E3A5F', borderRadius: 8 }}
                  labelStyle={{ color: '#94A3B8' }}
                  itemStyle={{ color: '#60A5FA' }}
                />
                <Area dataKey="risk" stroke="#1D4ED8" fill="url(#riskGrad)" strokeWidth={2} dot={{ fill: '#1D4ED8', r: 3 }} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-44 items-center justify-center">
              <p className="text-sm" style={{ color: '#334155' }}>No scan data yet — run your first scan</p>
            </div>
          )}
        </div>

        {/* Severity breakdown */}
        <div
          className="rounded-lg p-5"
          style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}
        >
          <p className="text-sm font-medium mb-4" style={{ color: '#E2E8F0' }}>
            Finding severity
          </p>
          {completedScans.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart
                layout="vertical"
                data={['CRITICAL','HIGH','MEDIUM','LOW'].map(sev => ({
                  name: sev,
                  count: completedScans.reduce((a: number, s: any) =>
                    a + (s.finding_counts?.[sev] ?? 0), 0),
                }))}
                margin={{ left: 10, right: 10 }}
              >
                <XAxis type="number" tick={{ fill: '#475569', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis dataKey="name" type="category" width={60} tick={{ fill: '#94A3B8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: '#0F172A', border: '1px solid #1E3A5F', borderRadius: 8 }}
                  itemStyle={{ color: '#60A5FA' }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={14}>
                  {['CRITICAL','HIGH','MEDIUM','LOW'].map((sev, i) => (
                    <Cell key={i} fill={SEV_COLOR[sev]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-44 items-center justify-center">
              <p className="text-sm" style={{ color: '#334155' }}>No data</p>
            </div>
          )}
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">

        {/* Recent scans */}
        <div
          className="rounded-lg p-5"
          style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}
        >
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>Recent scans</p>
            <Link href="/dashboard/scans" className="text-xs" style={{ color: '#60A5FA' }}>
              View all →
            </Link>
          </div>
          {scansLoading ? (
            <div className="space-y-2">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-14 rounded-lg animate-pulse" style={{ background: '#0F172A' }} />
              ))}
            </div>
          ) : (scans ?? []).length === 0 ? (
            <div className="flex h-40 flex-col items-center justify-center gap-3">
              <Clock className="h-8 w-8" style={{ color: '#334155' }} />
              <p className="text-sm" style={{ color: '#475569' }}>No scans yet</p>
              <Link
                href="/dashboard/scans/new"
                className="text-xs px-3 py-1.5 rounded-md"
                style={{ background: '#1D4ED8', color: '#EFF6FF' }}
              >
                Launch first scan
              </Link>
            </div>
          ) : (
            <div className="space-y-2">
              {(scans ?? []).slice(0, 5).map((scan: any) => (
                <ScanRow key={scan.id} scan={scan} />
              ))}
            </div>
          )}
        </div>

        {/* Critical findings */}
        <div
          className="rounded-lg p-5"
          style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}
        >
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>Critical findings</p>
            <Link href="/dashboard/findings?severity=CRITICAL" className="text-xs" style={{ color: '#60A5FA' }}>
              View all →
            </Link>
          </div>
          {!findings || findings.length === 0 ? (
            <div className="flex h-40 flex-col items-center justify-center gap-2">
              <Shield className="h-8 w-8" style={{ color: '#14532D' }} />
              <p className="text-sm" style={{ color: '#86EFAC' }}>No critical findings</p>
              <p className="text-xs" style={{ color: '#475569' }}>Fortified and defended</p>
            </div>
          ) : (
            <div className="space-y-2">
              {findings.slice(0, 5).map((f: any) => (
                <FindingRow key={f.id} finding={f} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
