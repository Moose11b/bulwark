'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'next/navigation'
import { api } from '@/lib/api'
import { Target, Shield, ChevronDown } from 'lucide-react'
import { severityColor } from '@/lib/utils'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer,
} from 'recharts'

const PHASE_ICONS = ['🔍','⚙️','📦','⚡','💾','📡','🎯']
function heatColor(pct: number) {
  if (pct >= 80) return '#FCA5A5'
  if (pct >= 60) return '#FDBA74'
  if (pct >= 40) return '#FDE68A'
  if (pct >= 20) return '#60A5FA'
  return '#334155'
}

export default function KillChainPage() {
  const params = useSearchParams()
  const scanId = params.get('scan')
  const [activePhase, setActivePhase] = useState<string | null>(null)

  const { data: scans } = useQuery({
    queryKey: ['scans-completed'],
    queryFn: () => api.get('/api/scans?limit=20&status=completed').then(r => r.data),
    enabled: !scanId,
  })

  const [selectedScan, setSelectedScan] = useState(scanId ?? '')
  const effectiveScan = selectedScan || (scans?.[0]?.id ?? '')

  const { data: report, isLoading } = useQuery({
    queryKey: ['killchain', effectiveScan],
    queryFn: () => api.get(`/api/killchain/scan/${effectiveScan}`).then(r => r.data),
    enabled: !!effectiveScan,
  })

  const phase = report?.phases?.find((p: any) => p.id === activePhase)

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color:'#E2E8F0' }}>
            <Target className="h-5 w-5" style={{ color:'#FCA5A5' }} /> Cyber Kill Chain
          </h1>
          <p className="text-sm mt-0.5" style={{ color:'#64748B' }}>Lockheed Martin 7-phase adversary mapping</p>
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
          <p className="text-sm" style={{ color:'#475569' }}>Select a completed scan to view kill chain analysis</p>
        </div>
      ) : isLoading ? (
        <div className="flex h-64 items-center justify-center">
          <div className="h-8 w-8 rounded-full border-2 animate-spin"
            style={{ borderColor:'#1D4ED8', borderTopColor:'transparent' }} />
        </div>
      ) : report && (
        <>
          {/* Stat cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label:'Total findings', value:report.total_findings, color:'#FDBA74' },
              { label:'Exposed phases', value:`${report.exposed_phases}/7`, color:'#FCA5A5' },
              { label:'Furthest phase', value:report.highest_phase_name, color:heatColor((report.highest_phase/7)*100) },
              { label:'Clean phases', value:7-report.exposed_phases, color:'#86EFAC' },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-lg p-4"
                style={{ background:'#1E293B', border:'0.5px solid #1E3A5F' }}>
                <p className="text-xs mb-1" style={{ color:'#64748B' }}>{label}</p>
                <p className="text-lg font-bold truncate" style={{ color }}>{value}</p>
              </div>
            ))}
          </div>

          {/* Highest phase warning */}
          {report.highest_phase >= 3 && (
            <div className="rounded-lg p-4 flex items-start gap-3"
              style={{ background:'#7F1D1D22', border:'0.5px solid #7F1D1D55' }}>
              <Shield className="h-5 w-5 shrink-0 mt-0.5" style={{ color:'#FCA5A5' }} />
              <div>
                <p className="text-sm font-medium" style={{ color:'#FCA5A5' }}>
                  Attacker progression reaches Phase {report.highest_phase}: {report.highest_phase_name}
                </p>
                <p className="text-xs mt-0.5" style={{ color:'#F87171' }}>
                  Remediate earliest exposed phases first to break the kill chain before exploitation.
                </p>
              </div>
            </div>
          )}

          {/* Phase selector */}
          <div className="grid grid-cols-7 gap-2">
            {(report.phases ?? []).map((p: any) => (
              <button key={p.id} onClick={() => setActivePhase(prev => prev === p.id ? null : p.id)}
                className="flex flex-col items-center gap-1 rounded-lg p-3 transition-all text-center"
                style={{
                  background: activePhase === p.id ? '#1D4ED820' : '#1E293B',
                  border: `0.5px solid ${activePhase === p.id ? '#1D4ED8' : p.count > 0 ? heatColor(p.heat_pct)+'44' : '#1E3A5F'}`,
                }}>
                <span className="text-xs" style={{ color:'#475569' }}>Phase {p.phase}</span>
                <span className="text-lg">{PHASE_ICONS[p.phase-1]}</span>
                <span className="text-[10px] font-medium leading-tight" style={{ color:'#94A3B8' }}>{p.name}</span>
                <span className="text-base font-bold" style={{ color: p.count > 0 ? heatColor(p.heat_pct) : '#334155' }}>
                  {p.count}
                </span>
              </button>
            ))}
          </div>

          {/* Phase detail */}
          {phase && (
            <div className="rounded-lg p-5 space-y-4"
              style={{ background:'#1E293B', border:`0.5px solid ${heatColor(phase.heat_pct)}44` }}>
              <div className="flex items-start gap-3">
                <div className="rounded-lg p-2.5 text-xl"
                  style={{ background:`${heatColor(phase.heat_pct)}15` }}>
                  {PHASE_ICONS[phase.phase-1]}
                </div>
                <div>
                  <p className="text-sm font-semibold" style={{ color:'#E2E8F0' }}>
                    Phase {phase.phase} — {phase.name}
                  </p>
                  <p className="text-xs mt-0.5" style={{ color:'#64748B' }}>{phase.description}</p>
                </div>
                <span className="ml-auto text-xs rounded-full px-2 py-0.5"
                  style={{ background:`${heatColor(phase.heat_pct)}22`, color:heatColor(phase.heat_pct) }}>
                  Heat {phase.heat_pct}%
                </span>
              </div>
              <div className="rounded-md px-3 py-2.5"
                style={{ background:'#1D4ED820', border:'0.5px solid #1D4ED855' }}>
                <p className="text-xs font-medium mb-0.5" style={{ color:'#60A5FA' }}>Defender action</p>
                <p className="text-xs" style={{ color:'#93C5FD' }}>{phase.defender_action}</p>
              </div>
              <div className="space-y-2">
                {phase.findings.map((f: any, i: number) => (
                  <div key={i} className="flex items-center gap-3 rounded-md px-3 py-2"
                    style={{ background:'#0F172A', border:'0.5px solid #1E3A5F' }}>
                    <span className="text-xs font-medium rounded-full px-2 py-0.5 shrink-0"
                      style={{ background:`${severityColor(f.severity)}22`, color:severityColor(f.severity) }}>
                      {f.severity}
                    </span>
                    <p className="text-xs" style={{ color:'#CBD5E1' }}>{f.title}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Bar chart */}
          <div className="rounded-lg p-5" style={{ background:'#1E293B', border:'0.5px solid #1E3A5F' }}>
            <p className="text-sm font-medium mb-4" style={{ color:'#E2E8F0' }}>Findings by phase</p>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={report.bar_data ?? []} margin={{ left:0, right:10 }}>
                <XAxis dataKey="phase" tick={{ fill:'#475569', fontSize:10 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill:'#475569', fontSize:11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background:'#0F172A', border:'1px solid #1E3A5F', borderRadius:8 }}
                  labelStyle={{ color:'#94A3B8' }} itemStyle={{ color:'#60A5FA' }} />
                <Bar dataKey="count" name="Findings" radius={[4,4,0,0]} barSize={28}>
                  {(report.bar_data ?? []).map((entry: any, i: number) => (
                    <Cell key={i} fill={heatColor(entry.heat)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </div>
  )
}
