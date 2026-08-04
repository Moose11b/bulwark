'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { toast } from 'sonner'
import { Zap, Filter, ExternalLink } from 'lucide-react'
import { severityColor, formatRelative } from '@/lib/utils'

const SEV_LIST = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const STATUS_LIST = ['open', 'triaged', 'in_progress', 'fixed', 'false_positive', 'accepted_risk']

const SEV_BG: Record<string, string> = {
  CRITICAL:'#7F1D1D33', HIGH:'#7C2D1233', MEDIUM:'#71360233', LOW:'#14532D33', INFO:'#1E3A5F33',
}
const STATUS_COLOR: Record<string, string> = {
  open:'#FCA5A5', triaged:'#FDBA74', in_progress:'#93C5FD',
  fixed:'#86EFAC', false_positive:'#475569', accepted_risk:'#64748B',
}

export default function FindingsPage() {
  const qc = useQueryClient()
  const [sevFilter, setSevFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [kevOnly, setKevOnly] = useState(false)

  const params = new URLSearchParams()
  if (sevFilter !== 'all') params.set('severity', sevFilter)
  if (statusFilter !== 'all') params.set('status', statusFilter)
  if (kevOnly) params.set('kev_only', 'true')
  params.set('limit', '100')

  const { data: findings, isLoading } = useQuery({
    queryKey: ['findings', sevFilter, statusFilter, kevOnly],
    queryFn: () => api.get(`/api/findings?${params}`).then(r => r.data),
  })

  const { data: stats } = useQuery({
    queryKey: ['findings-stats'],
    queryFn: () => api.get('/api/findings/stats').then(r => r.data),
  })

  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.patch(`/api/findings/${id}`, { status }),
    onSuccess: () => {
      toast.success('Finding updated')
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['findings-stats'] })
    },
  })

  return (
    <div className="space-y-5 animate-fade-in">

      {/* Header + stats */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: '#E2E8F0' }}>
            <Zap className="h-5 w-5" style={{ color: '#FDBA74' }} />
            Findings
          </h1>
          <p className="text-sm mt-0.5" style={{ color: '#64748B' }}>
            {stats?.total ?? 0} total · {stats?.open_count ?? 0} open · {stats?.kev_count ?? 0} CISA KEV
          </p>
        </div>
        <div className="flex gap-3">
          {SEV_LIST.map(s => (
            <div key={s} className="text-center">
              <p className="text-lg font-bold" style={{ color: severityColor(s) }}>
                {stats?.by_severity?.[s] ?? 0}
              </p>
              <p className="text-xs" style={{ color: '#475569' }}>{s[0]}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap rounded-lg px-4 py-3"
        style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
        <Filter className="h-3.5 w-3.5 shrink-0" style={{ color: '#475569' }} />
        <div className="flex gap-1.5 flex-wrap">
          {['all', ...SEV_LIST].map(s => (
            <button key={s} onClick={() => setSevFilter(s)}
              className="rounded-full px-2.5 py-0.5 text-xs capitalize transition-colors"
              style={{
                background: sevFilter === s ? '#1D4ED8' : 'transparent',
                color: sevFilter === s ? '#EFF6FF' : '#94A3B8',
                border: `0.5px solid ${sevFilter === s ? '#1D4ED8' : '#334155'}`,
              }}>
              {s}
            </button>
          ))}
        </div>
        <div className="w-px h-4" style={{ background: '#1E3A5F' }} />
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="text-xs rounded-md px-2 py-1 outline-none"
          style={{ background: '#0F172A', border: '0.5px solid #1E3A5F', color: '#94A3B8' }}
        >
          <option value="all">All statuses</option>
          {STATUS_LIST.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
        </select>
        <button
          onClick={() => setKevOnly(!kevOnly)}
          className="flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs transition-colors"
          style={{
            background: kevOnly ? '#7F1D1D33' : 'transparent',
            color: kevOnly ? '#FCA5A5' : '#94A3B8',
            border: `0.5px solid ${kevOnly ? '#7F1D1D55' : '#334155'}`,
          }}>
          CISA KEV only
        </button>
      </div>

      {/* Findings list */}
      <div className="rounded-lg overflow-hidden" style={{ border: '0.5px solid #1E3A5F' }}>
        {isLoading ? (
          Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="h-16 animate-pulse" style={{ background: '#1E293B', borderTop: i > 0 ? '0.5px solid #1E3A5F' : undefined }} />
          ))
        ) : (findings ?? []).length === 0 ? (
          <div className="flex flex-col items-center py-16 gap-2" style={{ background: '#1E293B' }}>
            <Zap className="h-8 w-8" style={{ color: '#334155' }} />
            <p className="text-sm" style={{ color: '#475569' }}>No findings match your filters</p>
          </div>
        ) : (
          (findings ?? []).map((f: any, i: number) => (
            <div key={f.id}
              className="flex items-start gap-3 px-4 py-3"
              style={{ background: '#1E293B', borderTop: i > 0 ? '0.5px solid #1E3A5F' : undefined }}>

              {/* Severity badge */}
              <span className="text-xs font-medium rounded-full px-2 py-0.5 shrink-0 mt-0.5"
                style={{ background: SEV_BG[f.severity], color: severityColor(f.severity) }}>
                {f.severity}
              </span>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between gap-2 flex-wrap">
                  <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>{f.title}</p>
                  <div className="flex items-center gap-2 shrink-0">
                    {f.is_in_kev && (
                      <span className="text-xs font-medium rounded px-1.5 py-0.5"
                        style={{ background: '#7F1D1D33', color: '#FCA5A5' }}>KEV</span>
                    )}
                    {f.cvss_score > 0 && (
                      <span className="text-xs" style={{ color: '#64748B' }}>
                        CVSS {f.cvss_score.toFixed(1)}
                      </span>
                    )}
                    {f.cve_id?.startsWith('CVE-') && (
                      <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`}
                        target="_blank" rel="noopener noreferrer">
                        <ExternalLink className="h-3.5 w-3.5" style={{ color: '#475569' }} />
                      </a>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-3 mt-1 flex-wrap">
                  <span className="text-xs" style={{ color: '#475569' }}>{f.source}</span>
                  {f.owasp_category && (
                    <span className="text-xs" style={{ color: '#475569' }}>{f.owasp_category}</span>
                  )}
                  <span className="text-xs" style={{ color: '#334155' }}>{formatRelative(f.first_seen)}</span>
                </div>
              </div>

              {/* Status selector */}
              <select
                value={f.status}
                onChange={e => updateStatus.mutate({ id: f.id, status: e.target.value })}
                className="text-xs rounded-md px-2 py-1 outline-none shrink-0"
                style={{
                  background: '#0F172A',
                  border: `0.5px solid ${STATUS_COLOR[f.status] ?? '#1E3A5F'}44`,
                  color: STATUS_COLOR[f.status] ?? '#94A3B8',
                }}>
                {STATUS_LIST.map(s => (
                  <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
                ))}
              </select>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
