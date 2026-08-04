'use client'

import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { api } from '@/lib/api'
import { formatRelative, riskColor, severityColor } from '@/lib/utils'
import {
  Shield, Target, ShieldAlert, CheckSquare,
  FileText, ExternalLink, ChevronLeft, Clock, Zap,
} from 'lucide-react'

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'PASS']

const SEV_BG: Record<string, string> = {
  CRITICAL: '#7F1D1D33', HIGH: '#7C2D1233',
  MEDIUM: '#71360233', LOW: '#14532D33', INFO: '#1E3A5F33',
}

function ProgressBar({ scan }: { scan: any }) {
  const pct = scan.progress ?? 0
  const isRunning = scan.status === 'running'
  const color = scan.status === 'failed' ? '#FCA5A5' : scan.status === 'completed' ? '#86EFAC' : '#60A5FA'

  return (
    <div className="rounded-lg p-5" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
      <div className="flex items-center justify-between mb-3">
        <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>
          {scan.progress_message ?? 'Initialising...'}
        </p>
        <span className="text-sm font-bold" style={{ color }}>{pct}%</span>
      </div>
      <div className="h-2 rounded-full overflow-hidden" style={{ background: '#0F172A' }}>
        <div
          className={`h-2 rounded-full transition-all duration-500 ${isRunning ? 'animate-pulse' : ''}`}
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
    </div>
  )
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const wsRef = useRef<WebSocket | null>(null)
  const [sevFilter, setSevFilter] = useState<string>('all')

  const { data: scan } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => api.get(`/api/scans/${id}`).then(r => r.data),
    // v5 hands the callback the Query, not the data. Reading `.status` off
    // the argument directly always yielded undefined, so this returned false
    // and polling never ran — leaving the page stuck on the first response if
    // the websocket dropped or was never authorised.
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === 'running' || status === 'queued' ? 3000 : false
    },
  })

  const { data: findings } = useQuery({
    queryKey: ['scan-findings', id, sevFilter],
    queryFn: () => {
      // Built with URLSearchParams: string-concatenating the filter produced
      // `/findings&limit=100` (no `?`) whenever sevFilter was 'all', which is
      // a different path entirely and 404s.
      const params = new URLSearchParams({ limit: '100' })
      if (sevFilter !== 'all') params.set('severity', sevFilter)
      return api.get(`/api/scans/${id}/findings?${params}`).then(r => r.data)
    },
    enabled: scan?.status === 'completed',
  })

  // WebSocket for live progress
  useEffect(() => {
    if (!id || scan?.status === 'completed' || scan?.status === 'failed') return

    let cancelled = false
    const connect = async () => {
      // Fetch a fresh Clerk token to authenticate the socket
      let token = ''
      try {
        const clerk = (window as any).Clerk
        if (clerk?.session) {
          token = (await clerk.session.getToken()) ?? ''
        }
      } catch {
        // no token — socket will be rejected, polling still covers updates
      }
      if (cancelled) return

      const base = process.env.NEXT_PUBLIC_API_URL?.replace('http', 'ws') ?? 'ws://localhost:8000'
      const wsUrl = `${base}/api/scans/${id}/ws?token=${encodeURIComponent(token)}`
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws
      ws.onmessage = () => {
        qc.invalidateQueries({ queryKey: ['scan', id] })
      }
      // The socket is an accelerator, not the source of truth: it can be
      // rejected (no token), drop, or miss events published before it
      // subscribed. Polling above is what actually guarantees the page
      // observes completion, so a socket failure is only worth logging.
      ws.onerror = () => console.warn('[scan] progress socket error; falling back to polling')
    }
    connect()

    return () => {
      cancelled = true
      wsRef.current?.close()
    }
  }, [id, scan?.status, qc])

  if (!scan) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="h-8 w-8 rounded-full border-2 border-t-transparent animate-spin"
          style={{ borderColor: '#1D4ED8', borderTopColor: 'transparent' }} />
      </div>
    )
  }

  const isRunning = scan.status === 'running' || scan.status === 'queued'
  const totalFindings = Object.values(scan.finding_counts ?? {}).reduce((a: number, v: any) => a + (Number(v) || 0), 0)

  return (
    <div className="space-y-5 animate-fade-in">

      {/* Back + header */}
      <div>
        <Link href="/dashboard/scans" className="flex items-center gap-1 text-xs mb-3"
          style={{ color: '#475569' }}>
          <ChevronLeft className="h-3 w-3" /> All scans
        </Link>
        <div className="flex items-start justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-lg font-semibold" style={{ color: '#E2E8F0' }}>{scan.target}</h1>
            <div className="flex items-center gap-3 mt-1 flex-wrap">
              <span className="text-xs rounded-full px-2 py-0.5 capitalize"
                style={{ background: '#1E3A5F', color: '#94A3B8' }}>
                {scan.scan_type}
              </span>
              <span className="text-xs" style={{ color: '#475569' }}>
                {formatRelative(scan.created_at)}
              </span>
            </div>
          </div>
          {scan.status === 'completed' && (
            <div className="text-right">
              <p className="text-3xl font-bold" style={{ color: riskColor(scan.risk_score) }}>
                {Math.round(scan.risk_score)}
              </p>
              <p className="text-xs" style={{ color: '#475569' }}>risk score</p>
            </div>
          )}
        </div>
      </div>

      {/* Progress (running) */}
      {isRunning && <ProgressBar scan={scan} />}

      {/* Stat cards */}
      {scan.status === 'completed' && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {SEV_ORDER.filter(s => s !== 'PASS').map(sev => (
            <div key={sev} className="rounded-lg p-4" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
              <p className="text-xs mb-1" style={{ color: '#475569' }}>{sev}</p>
              <p className="text-2xl font-bold" style={{ color: severityColor(sev) }}>
                {scan.finding_counts?.[sev] ?? 0}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Analysis links */}
      {scan.status === 'completed' && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { label: 'Kill Chain',   href: `/dashboard/killchain?scan=${id}`, icon: Target,      color: '#FCA5A5' },
            { label: 'OWASP Top 10', href: `/dashboard/owasp?scan=${id}`,     icon: ShieldAlert, color: '#FDBA74' },
            { label: 'Compliance',   href: `/dashboard/compliance?scan=${id}`, icon: CheckSquare, color: '#86EFAC' },
            { label: 'Report',       href: `/dashboard/reports?scan=${id}`,   icon: FileText,    color: '#93C5FD' },
          ].map(({ label, href, icon: Icon, color }) => (
            <Link key={label} href={href}
              className="flex items-center gap-2.5 rounded-lg p-3 transition-colors hover:bg-white/[.02]"
              style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
              <div className="rounded-md p-1.5" style={{ background: `${color}15` }}>
                <Icon className="h-4 w-4" style={{ color }} />
              </div>
              <span className="text-sm font-medium" style={{ color: '#CBD5E1' }}>{label}</span>
              <ExternalLink className="h-3.5 w-3.5 ml-auto" style={{ color: '#334155' }} />
            </Link>
          ))}
        </div>
      )}

      {/* Findings */}
      {scan.status === 'completed' && (
        <div className="rounded-lg overflow-hidden" style={{ border: '0.5px solid #1E3A5F' }}>
          <div className="flex items-center justify-between px-4 py-3"
            style={{ background: '#0C1628', borderBottom: '0.5px solid #1E3A5F' }}>
            <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>
              Findings ({totalFindings})
            </p>
            <div className="flex gap-1.5">
              {['all', ...SEV_ORDER.filter(s => s !== 'PASS')].map(s => (
                <button key={s} onClick={() => setSevFilter(s)}
                  className="rounded-full px-2.5 py-0.5 text-xs capitalize transition-colors"
                  style={{
                    background: sevFilter === s ? '#1D4ED8' : '#1E293B',
                    color: sevFilter === s ? '#EFF6FF' : '#475569',
                  }}>
                  {s}
                </button>
              ))}
            </div>
          </div>

          {(findings ?? []).length === 0 ? (
            <div className="flex flex-col items-center py-12 gap-2" style={{ background: '#1E293B' }}>
              <Shield className="h-8 w-8" style={{ color: '#14532D' }} />
              <p className="text-sm" style={{ color: '#86EFAC' }}>
                {sevFilter === 'all' ? 'No findings' : `No ${sevFilter} findings`}
              </p>
            </div>
          ) : (
            <div>
              {(findings ?? []).map((f: any, i: number) => (
                <div key={f.id}
                  className="flex items-start gap-3 px-4 py-3 transition-colors hover:bg-white/[.02]"
                  style={{ background: '#1E293B', borderTop: i > 0 ? '0.5px solid #1E3A5F' : undefined }}>
                  <span className="text-xs font-medium rounded-full px-2 py-0.5 shrink-0 mt-0.5"
                    style={{ background: SEV_BG[f.severity], color: severityColor(f.severity) }}>
                    {f.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>{f.title}</p>
                    {f.description && (
                      <p className="text-xs mt-0.5 line-clamp-2" style={{ color: '#64748B' }}>
                        {f.description}
                      </p>
                    )}
                    <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                      {f.cvss_score > 0 && (
                        <span className="text-xs" style={{ color: '#475569' }}>
                          CVSS {f.cvss_score.toFixed(1)}
                        </span>
                      )}
                      {f.is_in_kev && (
                        <span className="text-xs font-medium rounded px-1.5 py-0.5"
                          style={{ background: '#7F1D1D33', color: '#FCA5A5' }}>
                          CISA KEV
                        </span>
                      )}
                      {f.owasp_category && (
                        <span className="text-xs" style={{ color: '#475569' }}>
                          {f.owasp_category}
                        </span>
                      )}
                      <span className="text-xs" style={{ color: '#334155' }}>{f.source}</span>
                    </div>
                    {f.remediation && (
                      <p className="text-xs mt-2 rounded px-2 py-1.5"
                        style={{ background: '#0F172A', color: '#94A3B8', border: '0.5px solid #1E3A5F' }}>
                        {f.remediation}
                      </p>
                    )}
                  </div>
                  {f.cve_id?.startsWith('CVE-') && (
                    <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`}
                      target="_blank" rel="noopener noreferrer" className="shrink-0 mt-0.5">
                      <ExternalLink className="h-3.5 w-3.5" style={{ color: '#475569' }} />
                    </a>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Error state */}
      {scan.status === 'failed' && (
        <div className="rounded-lg p-4" style={{ background: '#7F1D1D22', border: '0.5px solid #7F1D1D55' }}>
          <p className="text-sm font-medium" style={{ color: '#FCA5A5' }}>Scan failed</p>
          <p className="text-xs mt-1" style={{ color: '#F87171' }}>{scan.error_message}</p>
        </div>
      )}
    </div>
  )
}
