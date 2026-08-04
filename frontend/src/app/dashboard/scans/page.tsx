'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import Link from 'next/link'
import { api } from '@/lib/api'
import { Plus, Radar, ChevronRight, RefreshCw } from 'lucide-react'
import { formatRelative, riskColor, severityColor } from '@/lib/utils'

const STATUS_DOT: Record<string, string> = {
  completed: '#86EFAC', running: '#60A5FA',
  failed: '#FCA5A5',    queued: '#FDE68A', cancelled: '#475569',
}

const TYPE_LABEL: Record<string, string> = {
  full: 'Full', nmap: 'Ports', ssl: 'SSL', headers: 'Headers',
  dns: 'DNS', nikto: 'Nikto', nuclei: 'Nuclei', exposure: 'Exposure', osint: 'OSINT',
}

export default function ScansPage() {
  const [filter, setFilter] = useState<string>('all')

  const { data: scans, isLoading, refetch } = useQuery({
    queryKey: ['scans', filter],
    queryFn: () => api.get(`/api/scans?limit=50${filter !== 'all' ? `&status=${filter}` : ''}`).then(r => r.data),
    refetchInterval: 8000,
  })

  const filters = ['all', 'running', 'completed', 'failed', 'queued']

  return (
    <div className="space-y-5 animate-fade-in">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: '#E2E8F0' }}>Scans</h1>
          <p className="text-sm mt-0.5" style={{ color: '#64748B' }}>
            {(scans ?? []).length} scans {filter !== 'all' ? `· ${filter}` : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="rounded-lg p-2 transition-colors"
            style={{ background: '#1E293B', border: '0.5px solid #1E3A5F', color: '#64748B' }}
          >
            <RefreshCw className="h-4 w-4" />
          </button>
          <Link
            href="/dashboard/scans/new"
            className="flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium"
            style={{ background: '#1D4ED8', color: '#EFF6FF' }}
          >
            <Plus className="h-4 w-4" /> New scan
          </Link>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap">
        {filters.map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className="rounded-full px-3 py-1 text-xs font-medium capitalize transition-colors"
            style={{
              background: filter === f ? '#1D4ED8' : '#1E293B',
              color: filter === f ? '#EFF6FF' : '#94A3B8',
              border: `0.5px solid ${filter === f ? '#1D4ED8' : '#1E3A5F'}`,
            }}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="rounded-lg overflow-hidden" style={{ border: '0.5px solid #1E3A5F' }}>
        {/* Header row */}
        <div
          className="grid grid-cols-12 gap-4 px-4 py-2 text-xs font-medium"
          style={{ background: '#0C1628', color: '#475569' }}
        >
          <div className="col-span-4">Target</div>
          <div className="col-span-2">Type</div>
          <div className="col-span-2">Status</div>
          <div className="col-span-2">Risk</div>
          <div className="col-span-1">Findings</div>
          <div className="col-span-1" />
        </div>

        {/* Rows */}
        {isLoading ? (
          Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-14 animate-pulse" style={{ background: '#1E293B', borderTop: '0.5px solid #1E3A5F' }} />
          ))
        ) : (scans ?? []).length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3"
            style={{ background: '#1E293B' }}>
            <Radar className="h-10 w-10" style={{ color: '#334155' }} />
            <p className="text-sm" style={{ color: '#475569' }}>No scans found</p>
            <Link href="/dashboard/scans/new"
              className="text-xs px-3 py-1.5 rounded-md"
              style={{ background: '#1D4ED8', color: '#EFF6FF' }}>
              Launch first scan
            </Link>
          </div>
        ) : (
          (scans ?? []).map((scan: any) => {
            const totalFindings = Object.values(scan.finding_counts ?? {}).reduce((a: number, v: any) => a + v, 0)
            return (
              <Link
                key={scan.id}
                href={`/dashboard/scans/${scan.id}`}
                className="grid grid-cols-12 gap-4 px-4 py-3 items-center transition-colors hover:bg-white/[.02]"
                style={{ background: '#1E293B', borderTop: '0.5px solid #1E3A5F' }}
              >
                <div className="col-span-4 min-w-0">
                  <p className="text-sm font-medium truncate" style={{ color: '#E2E8F0' }}>{scan.target}</p>
                  <p className="text-xs" style={{ color: '#475569' }}>{formatRelative(scan.created_at)}</p>
                </div>
                <div className="col-span-2">
                  <span className="text-xs rounded px-2 py-0.5"
                    style={{ background: '#1E3A5F', color: '#94A3B8' }}>
                    {TYPE_LABEL[scan.scan_type] ?? scan.scan_type?.toUpperCase()}
                  </span>
                </div>
                <div className="col-span-2 flex items-center gap-2">
                  <div className="h-1.5 w-1.5 rounded-full"
                    style={{ background: STATUS_DOT[scan.status] ?? '#475569' }} />
                  <span className="text-xs capitalize" style={{ color: '#94A3B8' }}>{scan.status}</span>
                </div>
                <div className="col-span-2">
                  {scan.status === 'completed' ? (
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1 rounded-full" style={{ background: '#0F172A' }}>
                        <div className="h-1 rounded-full transition-all"
                          style={{ width: `${Math.min(scan.risk_score, 100)}%`, background: riskColor(scan.risk_score) }} />
                      </div>
                      <span className="text-xs font-medium w-6 text-right"
                        style={{ color: riskColor(scan.risk_score) }}>
                        {Math.round(scan.risk_score)}
                      </span>
                    </div>
                  ) : scan.status === 'running' ? (
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: '#0F172A' }}>
                        <div className="h-1 w-1/3 rounded-full animate-pulse" style={{ background: '#60A5FA' }} />
                      </div>
                      <span className="text-xs" style={{ color: '#60A5FA' }}>{scan.progress}%</span>
                    </div>
                  ) : <span className="text-xs" style={{ color: '#334155' }}>—</span>}
                </div>
                <div className="col-span-1">
                  <span className="text-sm font-medium" style={{ color: totalFindings > 0 ? '#FDBA74' : '#334155' }}>
                    {totalFindings || '—'}
                  </span>
                </div>
                <div className="col-span-1 flex justify-end">
                  <ChevronRight className="h-4 w-4" style={{ color: '#334155' }} />
                </div>
              </Link>
            )
          })
        )}
      </div>
    </div>
  )
}
