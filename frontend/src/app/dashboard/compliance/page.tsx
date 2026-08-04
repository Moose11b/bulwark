'use client'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'next/navigation'
import { api } from '@/lib/api'
import { CheckSquare, ChevronDown, ChevronUp } from 'lucide-react'
import { severityColor } from '@/lib/utils'

const FRAMEWORKS = [
  { id:'pci_dss',   label:'PCI-DSS v4.0',     color:'#60A5FA' },
  { id:'iso_27001', label:'ISO 27001:2022',   color:'#86EFAC' },
  { id:'nist_csf',  label:'NIST CSF 2.0',     color:'#FDBA74' },
  { id:'cis_v8',    label:'CIS Controls v8',  color:'#C4B5FD' },
]

function ControlRow({ control, name, findings }: { control: string; name?: string; findings: any[] }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg overflow-hidden" style={{ border:'0.5px solid #1E3A5F' }}>
      <button className="w-full flex items-center gap-3 px-4 py-2.5 text-left"
        style={{ background:'#1E293B' }} onClick={() => setOpen(o => !o)}>
        <span className="text-xs font-mono font-medium rounded px-1.5 py-0.5 shrink-0"
          style={{ background:'#1E3A5F', color:'#94A3B8' }}>{control}</span>
        <span className="text-xs flex-1 truncate" style={{ color:'#CBD5E1' }}>
          {name && name !== control ? name : `${findings.length} finding${findings.length !== 1 ? 's' : ''}`}
        </span>
        <span className="text-xs shrink-0" style={{ color:'#475569' }}>{findings.length}</span>
        {open ? <ChevronUp className="h-3.5 w-3.5 shrink-0" style={{ color:'#475569' }} />
              : <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color:'#475569' }} />}
      </button>
      {open && findings.map((f, i) => (
        <div key={i} className="flex items-center gap-3 px-4 py-2"
          style={{ background:'#0F172A', borderTop:'0.5px solid #1E3A5F' }}>
          <span className="text-xs rounded-full px-2 py-0.5 shrink-0"
            style={{ background:`${severityColor(f.severity)}22`, color:severityColor(f.severity) }}>
            {f.severity}
          </span>
          <p className="text-xs" style={{ color:'#CBD5E1' }}>{f.title}</p>
        </div>
      ))}
    </div>
  )
}

export default function CompliancePage() {
  const params = useSearchParams()
  const scanId = params.get('scan')
  const [selectedScan, setSelectedScan] = useState(scanId ?? '')
  const [activeFramework, setActiveFramework] = useState('pci_dss')

  const { data: scans } = useQuery({
    queryKey:['scans-completed'],
    queryFn: () => api.get('/api/scans?limit=20&status=completed').then(r => r.data),
    enabled: !scanId,
  })
  const effectiveScan = selectedScan || (scans?.[0]?.id ?? '')
  const { data: report, isLoading } = useQuery({
    queryKey:['compliance', effectiveScan],
    queryFn: () => api.get(`/api/compliance/scan/${effectiveScan}`).then(r => r.data),
    enabled: !!effectiveScan,
  })

  const fw = FRAMEWORKS.find(f => f.id === activeFramework)!
  const data = report?.[activeFramework] ?? []

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color:'#E2E8F0' }}>
            <CheckSquare className="h-5 w-5" style={{ color:'#86EFAC' }} /> Compliance
          </h1>
          <p className="text-sm mt-0.5" style={{ color:'#64748B' }}>PCI-DSS · ISO 27001 · NIST CSF mapping</p>
        </div>
        {!scanId && scans && (
          <select value={selectedScan} onChange={e => setSelectedScan(e.target.value)}
            className="rounded-lg px-3 py-2 text-sm outline-none"
            style={{ background:'#1E293B', border:'0.5px solid #1E3A5F', color:'#E2E8F0' }}>
            <option value="">Select a scan</option>
            {scans.map((s: any) => <option key={s.id} value={s.id}>{s.target}</option>)}
          </select>
        )}
      </div>

      {!effectiveScan ? (
        <div className="flex h-64 items-center justify-center rounded-lg"
          style={{ background:'#1E293B', border:'0.5px solid #1E3A5F' }}>
          <p className="text-sm" style={{ color:'#475569' }}>Select a completed scan</p>
        </div>
      ) : (
        <>
          {/* Framework tabs */}
          <div className="flex gap-2">
            {FRAMEWORKS.map(f => (
              <button key={f.id} onClick={() => setActiveFramework(f.id)}
                className="rounded-lg px-4 py-2 text-xs font-medium transition-colors"
                style={{
                  background: activeFramework === f.id ? `${f.color}20` : '#1E293B',
                  color: activeFramework === f.id ? f.color : '#64748B',
                  border: `0.5px solid ${activeFramework === f.id ? f.color+'44' : '#1E3A5F'}`,
                }}>
                {f.label}
              </button>
            ))}
          </div>

          {/* Summary */}
          {report && (
            <div className="rounded-lg p-4 flex items-center gap-4"
              style={{ background:'#1E293B', border:`0.5px solid ${fw.color}44` }}>
              <div>
                <p className="text-2xl font-bold" style={{ color:fw.color }}>
                  {report[`${activeFramework}_controls_hit`] ?? data.length}
                </p>
                <p className="text-xs" style={{ color:'#475569' }}>controls relevant</p>
              </div>
              <div className="w-px h-10 self-center" style={{ background:'#1E3A5F' }} />
              <p className="text-xs" style={{ color:'#64748B' }}>
                Findings mapped to {fw.label} controls based on CWE identifiers
              </p>
            </div>
          )}

          {/* Disclaimer */}
          {report?.disclaimer && (
            <div className="rounded-lg p-3 flex items-start gap-2.5"
              style={{ background:'#78350F22', border:'0.5px solid #92400E55' }}>
              <span className="text-sm shrink-0" style={{ color:'#FDBA74' }}>&#9888;</span>
              <p className="text-xs leading-relaxed" style={{ color:'#FCD9A5' }}>
                {report.disclaimer}
              </p>
            </div>
          )}

          {/* Controls */}
          {isLoading ? (
            Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-12 rounded-lg animate-pulse" style={{ background:'#1E293B' }} />
            ))
          ) : data.length === 0 ? (
            <div className="flex h-40 items-center justify-center rounded-lg"
              style={{ background:'#1E293B', border:'0.5px solid #1E3A5F' }}>
              <p className="text-sm" style={{ color:'#334155' }}>No findings mapped to {fw.label}</p>
            </div>
          ) : (
            <div className="space-y-2">
              {data.map((item: any) => (
                <ControlRow key={item.control} control={item.control} name={item.name} findings={item.findings} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}
