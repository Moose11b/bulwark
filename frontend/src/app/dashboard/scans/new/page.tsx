'use client'

import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useRouter } from 'next/navigation'
import { api } from '@/lib/api'
import { toast } from 'sonner'
import { Shield, Radar, Globe, Lock, FileSearch, Search, Zap, Database, Eye } from 'lucide-react'

const SCAN_TYPES = [
  { id: 'full',     label: 'Full scan',    icon: Shield,     desc: 'All modules — ports, SSL, headers, DNS, Nikto, Nuclei, exposure', time: '5–15 min' },
  { id: 'nmap',     label: 'Port scan',    icon: Radar,      desc: 'Top 1000 TCP ports, service detection, banner grabbing', time: '1–3 min' },
  { id: 'ssl',      label: 'SSL/TLS',      icon: Lock,       desc: 'Certificate validity, protocol versions, cipher strength, HSTS', time: '<1 min' },
  { id: 'headers',  label: 'HTTP headers', icon: Globe,      desc: 'CSP, HSTS, X-Frame-Options, CORS, server disclosure', time: '<1 min' },
  { id: 'dns',      label: 'DNS recon',    icon: Search,     desc: 'SPF, DMARC, DNSSEC, CAA, zone transfer, subdomain enum', time: '1–2 min' },
  { id: 'nikto',    label: 'Nikto',        icon: FileSearch, desc: 'Web server misconfigurations, dangerous files, outdated software', time: '3–8 min' },
  { id: 'nuclei',   label: 'Nuclei',       icon: Zap,        desc: 'Template-based CVE and misconfiguration scanning', time: '3–10 min' },
  { id: 'exposure', label: 'Exposure',     icon: Database,   desc: 'Sensitive files, .env, .git, backup files, API key leaks', time: '1–2 min' },
  { id: 'osint',    label: 'OSINT',        icon: Eye,        desc: 'Passive recon — crt.sh, WHOIS, HIBP, VirusTotal, Wayback', time: '1–3 min' },
]

export default function NewScanPage() {
  const router = useRouter()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('full')
  const [assetId, setAssetId] = useState('')

  const { data: assets } = useQuery({
    queryKey: ['assets-list'],
    queryFn: () => api.get('/api/assets').then(r => r.data),
  })

  const launch = useMutation({
    mutationFn: () => api.post('/api/scans', {
      target: target.trim(),
      scan_type: scanType,
      asset_id: assetId || null,
    }),
    onSuccess: (res) => {
      toast.success('Scan launched')
      router.push(`/dashboard/scans/${res.data.id}`)
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail ?? 'Failed to launch scan')
    },
  })

  const selected = SCAN_TYPES.find(t => t.id === scanType)

  return (
    <div className="max-w-2xl space-y-6 animate-fade-in">
      <div>
        <h1 className="text-lg font-semibold" style={{ color: '#E2E8F0' }}>Launch new scan</h1>
        <p className="text-sm mt-0.5" style={{ color: '#64748B' }}>
          Configure your target and scan profile
        </p>
      </div>

      {/* Target */}
      <div className="rounded-lg p-5 space-y-4" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
        <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>Target</p>
        <input
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="example.com or 192.168.1.1"
          className="w-full rounded-lg px-3 py-2.5 text-sm outline-none transition-colors"
          style={{
            background: '#0F172A', border: '0.5px solid #1E3A5F',
            color: '#E2E8F0',
          }}
          onFocus={e => (e.target.style.borderColor = '#1D4ED8')}
          onBlur={e => (e.target.style.borderColor = '#1E3A5F')}
        />

        {/* Link to asset */}
        {assets && assets.length > 0 && (
          <div>
            <p className="text-xs mb-1.5" style={{ color: '#475569' }}>
              Link to asset (optional)
            </p>
            <select
              value={assetId}
              onChange={e => {
                setAssetId(e.target.value)
                const asset = assets.find((a: any) => a.id === e.target.value)
                if (asset) setTarget(asset.target)
              }}
              className="w-full rounded-lg px-3 py-2 text-sm outline-none"
              style={{ background: '#0F172A', border: '0.5px solid #1E3A5F', color: '#E2E8F0' }}
            >
              <option value="">— No asset —</option>
              {assets.map((a: any) => (
                <option key={a.id} value={a.id}>{a.name} ({a.target})</option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Scan type */}
      <div className="rounded-lg p-5 space-y-3" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
        <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>Scan profile</p>
        <div className="grid grid-cols-3 gap-2">
          {SCAN_TYPES.map(type => {
            const Icon = type.icon
            const active = scanType === type.id
            return (
              <button
                key={type.id}
                onClick={() => setScanType(type.id)}
                className="rounded-lg p-3 text-left transition-all"
                style={{
                  background: active ? '#1D4ED820' : '#0F172A',
                  border: `0.5px solid ${active ? '#1D4ED8' : '#1E3A5F'}`,
                }}
              >
                <Icon className="h-4 w-4 mb-1.5" style={{ color: active ? '#60A5FA' : '#475569' }} />
                <p className="text-xs font-medium" style={{ color: active ? '#E2E8F0' : '#94A3B8' }}>
                  {type.label}
                </p>
              </button>
            )
          })}
        </div>

        {/* Selected description */}
        {selected && (
          <div className="rounded-md px-3 py-2.5" style={{ background: '#0F172A', border: '0.5px solid #1E3A5F' }}>
            <div className="flex items-center justify-between mb-1">
              <p className="text-xs font-medium" style={{ color: '#E2E8F0' }}>{selected.label}</p>
              <span className="text-xs rounded-full px-2 py-0.5"
                style={{ background: '#1E3A5F', color: '#94A3B8' }}>
                ~{selected.time}
              </span>
            </div>
            <p className="text-xs" style={{ color: '#64748B' }}>{selected.desc}</p>
          </div>
        )}
      </div>

      {/* Launch */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => launch.mutate()}
          disabled={!target.trim() || launch.isPending}
          className="flex items-center gap-2 rounded-lg px-6 py-2.5 text-sm font-medium transition-all disabled:opacity-40"
          style={{ background: '#1D4ED8', color: '#EFF6FF' }}
        >
          <Shield className="h-4 w-4" />
          {launch.isPending ? 'Launching...' : 'Launch scan'}
        </button>
        <button
          type="button"
          onClick={() => router.back()}
          className="rounded-lg px-4 py-2.5 text-sm transition-colors"
          style={{ color: '#64748B' }}
        >
          Cancel
        </button>
      </div>
    </div>
  )
}
