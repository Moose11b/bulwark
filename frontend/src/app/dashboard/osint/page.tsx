'use client'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Eye, Search } from 'lucide-react'

export default function OSINTPage() {
  const [target, setTarget] = useState('')
  const [queried, setQueried] = useState('')
  const run = () => { if (target.trim()) setQueried(target.trim()) }
  const { data, isLoading } = useQuery({
    queryKey: ['osint', queried],
    queryFn: () => api.get(`/api/osint/${encodeURIComponent(queried)}/full`).then(r => r.data),
    enabled: !!queried,
  })
  const Card = ({ title, color, children }: any) => (
    <div className="rounded-lg p-4 space-y-2" style={{ background: '#1E293B', border: `0.5px solid ${color}33` }}>
      <p className="text-xs font-medium uppercase tracking-wide" style={{ color }}>{title}</p>
      {children}
    </div>
  )
  const Row = ({ label, value }: any) => value != null ? (
    <div className="flex justify-between text-xs gap-3">
      <span style={{ color: '#475569' }}>{label}</span>
      <span className="text-right" style={{ color: '#94A3B8' }}>{String(value)}</span>
    </div>
  ) : null

  return (
    <div className="space-y-5 animate-fade-in">
      <div>
        <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: '#E2E8F0' }}>
          <Eye className="h-5 w-5" style={{ color: '#93C5FD' }} /> OSINT
        </h1>
        <p className="text-sm mt-0.5" style={{ color: '#64748B' }}>Passive reconnaissance — no target interaction</p>
      </div>
      <div className="flex gap-2">
        <input value={target} onChange={e => setTarget(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && run()}
          placeholder="example.com"
          className="flex-1 rounded-lg px-3 py-2.5 text-sm outline-none"
          style={{ background: '#1E293B', border: '0.5px solid #1E3A5F', color: '#E2E8F0' }} />
        <button onClick={run} disabled={!target.trim() || isLoading}
          className="flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-40"
          style={{ background: '#1D4ED8', color: '#EFF6FF' }}>
          <Search className="h-4 w-4" />
          {isLoading ? 'Scanning...' : 'Run OSINT'}
        </button>
      </div>
      {isLoading && (
        <div className="flex h-48 items-center justify-center">
          <div className="h-8 w-8 rounded-full border-2 animate-spin"
            style={{ borderColor: '#1D4ED8', borderTopColor: 'transparent' }} />
        </div>
      )}
      {data && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Card title="WHOIS / ASN" color="#60A5FA">
            <Row label="Registrar" value={data.whois?.registrar} />
            <Row label="Registered" value={data.whois?.registered?.slice(0, 10)} />
            <Row label="Expires" value={data.whois?.expires?.slice(0, 10)} />
            <Row label="Country" value={data.whois?.country} />
            <Row label="ASN" value={data.whois?.asn} />
            <Row label="IP" value={data.whois?.ip} />
          </Card>
          <Card title="Certificate transparency" color="#86EFAC">
            <Row label="Subdomains found" value={data.crt?.subdomain_count} />
            <Row label="Total certs" value={data.crt?.cert_count} />
            {(data.crt?.subdomains ?? []).slice(0, 6).map((s: string, i: number) => (
              <p key={i} className="text-xs font-mono" style={{ color: '#64748B' }}>{s}</p>
            ))}
          </Card>
          <Card title="HIBP breach check" color="#FDBA74">
            {data.hibp?.breach_count === 0
              ? <p className="text-xs" style={{ color: '#86EFAC' }}>No breaches found</p>
              : <>
                  <Row label="Breaches" value={data.hibp?.breach_count} />
                  <Row label="Emails exposed" value={data.hibp?.total_emails_exposed} />
                </>}
            {data.hibp?.note && <p className="text-xs" style={{ color: '#475569' }}>{data.hibp.note}</p>}
          </Card>
          <Card title="VirusTotal" color="#FCA5A5">
            {data.virustotal?.note
              ? <p className="text-xs" style={{ color: '#475569' }}>{data.virustotal.note}</p>
              : <>
                  <Row label="Malicious" value={data.virustotal?.malicious} />
                  <Row label="Suspicious" value={data.virustotal?.suspicious} />
                  <Row label="Reputation" value={data.virustotal?.reputation} />
                </>}
          </Card>
        </div>
      )}
    </div>
  )
}
