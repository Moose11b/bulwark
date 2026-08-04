'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'next/navigation'
import { api } from '@/lib/api'
import { ShieldAlert, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react'
import { severityColor } from '@/lib/utils'
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar,
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
} from 'recharts'

const RISK_COLOR: Record<string, string> = {
  Critical:'#FCA5A5', High:'#FDBA74', Medium:'#FDE68A', Low:'#86EFAC',
}

function CategoryCard({ cat }: { cat: any }) {
  const [open, setOpen] = useState(false)
  const color = RISK_COLOR[cat.risk] ?? '#94A3B8'
  return (
    <div className="rounded-lg overflow-hidden" style={{ border:'0.5px solid #1E3A5F' }}>
      <button className="w-full flex items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-white/[.02]"
        style={{ background:'#1E293B' }} onClick={() => setOpen(o => !o)}>
        <span className="text-xs font-bold rounded px-1.5 py-0.5"
          style={{ background:`${color}22`, color }}>
          {cat.code}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate" style={{ color:'#E2E8F0' }}>{cat.name}</p>
          <p className="text-xs line-clamp-1" style={{ color:'#475569' }}>{cat.description}</p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <span className="text-sm font-bold" style={{ color: cat.count > 0 ? color : '#334155' }}>
            {cat.count}
          </span>
          {open ? <ChevronUp className="h-4 w-4" style={{ color:'#475569' }} />
                 : <ChevronDown className="h-4 w-4" style={{ color:'#475569' }} />}
        </div>
      </button>
      {open && (
        <div style={{ background:'#0F172A', borderTop:'0.5px solid #1E3A5F' }}>
          {cat.findings.length === 0 ? (
            <p className="px-4 py-3 text-xs" style={{ color:'#334155' }}>No findings in this category</p>
          ) : cat.findings.map((f: any, i: number) => (
            <div key={i} className="flex items-center gap-3 px-4 py-2.5"
              style={{ borderTop: i > 0 ? '0.5px solid #1E293B' : undefined }}>
              <span className="text-xs font-medium rounded-full px-2 py-0.5 shrink-0"
                style={{ background:`${severityColor(f.severity)}22`, color:severityColor(f.severity) }}>
                {f.severity}
              </span>
              <p className="text-xs flex-1 truncate" style={{ color:'#CBD5E1' }}>{f.title || f.cve_id}</p>
              {f.cve_id?.startsWith('CVE-') && (
                <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`}
                  target="_blank" rel="noopener noreferrer">
                  <ExternalLink className="h-3.5 w-3.5" style={{ color:'#475569' }} />
                </a>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function OWASPPage() {
  const params = useSearchParams()
  const scanId = params.get('scan')
  const [selectedScan, setSelectedScan] = useState(scanId ?? '')

  const { data: scans } = useQuery({
    queryKey: ['scans-completed'],
    queryFn: () => api.get('/api/scans?limit=20&status=completed').then(r => r.data),
    enabled: !scanId,
  })

  const effectiveScan = selectedScan || (scans?.[0]?.id ?? '')

  const { data: report, isLoading } = useQuery({
    queryKey: ['owasp', effectiveScan],
    queryFn: () => api.get(`/api/owasp/scan/${effectiveScan}`).then(r => r.data),
    enabled: !!effectiveScan,
  })

  const hit = (report?.categories ?? []).filter((c: any) => c.count > 0)
  const clean = (report?.categories ?? []).filter((c: any) => c.count === 0)

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color:'#E2E8F0' }}>
            <ShieldAlert className="h-5 w-5" style={{ color:'#FDBA74' }} /> OWASP Top 10
          </h1>
          <p className="text-sm mt-0.5" style={{ color:'#64748B' }}>OWASP Top 10 (2021) classification</p>
        </div>
        {!scanId && scans && (
          <select value={selectedScan} onChange={e => setSelectedScan(e.target.value)}
            className="rounded-lg px-3 py-2 text-sm outline-none"
            style={{ background:'#1E293B', border:'0.5px solid #1E3A5F', color:'#E2E8F0' }}>
            <option value="">Select a scan</option>
            {scans.map((s: any) => (
              <option key={s.id} value={s.id}>{s.target} — {new Date(s.created_at).toLocaleDateString()}</option>
            ))}
          </select>
        )}
      </div>

      {!effectiveScan ? (
        <div className="flex h-64 items-center justify-center rounded-lg"
          style={{ background:'#1E293B', border:'0.5px solid #1E3A5F' }}>
          <p className="text-sm" style={{ color:'#475569' }}>Select a completed scan</p>
        </div>
      ) : isLoading ? (
        <div className="flex h-64 items-center justify-center">
          <div className="h-8 w-8 rounded-full border-2 animate-spin"
            style={{ borderColor:'#1D4ED8', borderTopColor:'transparent' }} />
        </div>
      ) : report && (
        <>
          {/* Stats */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label:'Total findings', value:report.total_findings, color:'#FDBA74' },
              { label:'Categories hit', value:report.categories_hit, color:'#FCA5A5' },
              { label:'Categories clean', value:10-report.categories_hit, color:'#86EFAC' },
              { label:'Coverage', value:`${report.categories_hit}/10`, color:'#60A5FA' },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-lg p-4"
                style={{ background:'#1E293B', border:'0.5px solid #1E3A5F' }}>
                <p className="text-xs mb-1" style={{ color:'#64748B' }}>{label}</p>
                <p className="text-2xl font-bold" style={{ color }}>{value}</p>
              </div>
            ))}
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="rounded-lg p-5" style={{ background:'#1E293B', border:'0.5px solid #1E3A5F' }}>
              <p className="text-sm font-medium mb-3" style={{ color:'#E2E8F0' }}>Category radar</p>
              <ResponsiveContainer width="100%" height={280}>
                <RadarChart data={report.radar_data ?? []} cx="50%" cy="50%" outerRadius="70%">
                  <PolarGrid stroke="#1E3A5F" />
                  <PolarAngleAxis dataKey="name" tick={{ fill:'#475569', fontSize:9 }} />
                  <Radar name="Findings" dataKey="count" stroke="#F59E0B" fill="#F59E0B" fillOpacity={0.2} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
            <div className="rounded-lg p-5" style={{ background:'#1E293B', border:'0.5px solid #1E3A5F' }}>
              <p className="text-sm font-medium mb-3" style={{ color:'#E2E8F0' }}>Findings by category</p>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart layout="vertical"
                  data={(report.categories ?? []).map((c: any) => ({ name:c.code, count:c.count, risk:c.risk }))}
                  margin={{ left:10, right:20 }}>
                  <XAxis type="number" tick={{ fill:'#475569', fontSize:11 }} axisLine={false} tickLine={false} />
                  <YAxis dataKey="name" type="category" width={34} tick={{ fill:'#94A3B8', fontSize:11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background:'#0F172A', border:'1px solid #1E3A5F', borderRadius:8 }}
                    itemStyle={{ color:'#60A5FA' }} />
                  <Bar dataKey="count" name="Findings" radius={[0,4,4,0]} barSize={14}>
                    {(report.categories ?? []).map((c: any, i: number) => (
                      <Cell key={i} fill={RISK_COLOR[c.risk] ?? '#475569'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Categories with findings */}
          {hit.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide" style={{ color:'#475569' }}>
                Categories with findings ({hit.length})
              </p>
              {hit.map((cat: any) => <CategoryCard key={cat.code} cat={cat} />)}
            </div>
          )}

          {/* Clean categories */}
          {clean.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide" style={{ color:'#334155' }}>
                Clean ({clean.length})
              </p>
              {clean.map((cat: any) => <CategoryCard key={cat.code} cat={cat} />)}
            </div>
          )}
        </>
      )}
    </div>
  )
}
