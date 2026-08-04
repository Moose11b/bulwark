'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { toast } from 'sonner'
import { FolderOpen, Plus, Radar, X, ChevronRight } from 'lucide-react'
import { formatRelative, riskColor } from '@/lib/utils'

const RISK_COLOR: Record<string, string> = {
  critical:'#FCA5A5', high:'#FDBA74', medium:'#FDE68A', low:'#86EFAC',
}

const TYPE_ICON: Record<string, string> = {
  domain:'🌐', ip:'📡', cidr:'🔗', url:'🔒',
}

function NewAssetModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ name:'', target:'', asset_type:'domain', risk_tier:'medium', owner:'', tags:'' })

  const create = useMutation({
    mutationFn: () => api.post('/api/assets', {
      ...form,
      tags: form.tags ? form.tags.split(',').map(t => t.trim()) : [],
    }),
    onSuccess: () => {
      toast.success('Asset created')
      qc.invalidateQueries({ queryKey: ['assets'] })
      onClose()
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Failed to create asset'),
  })

  const inp = (field: string, ...rest: any[]) => ({
    value: (form as any)[field],
    onChange: (e: any) => setForm(f => ({ ...f, [field]: e.target.value })),
    className: 'w-full rounded-lg px-3 py-2 text-sm outline-none',
    style: { background:'#0F172A', border:'0.5px solid #1E3A5F', color:'#E2E8F0' },
    ...Object.fromEntries(rest),
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background:'rgba(0,0,0,0.7)' }}>
      <div className="w-full max-w-md rounded-xl p-6 space-y-4"
        style={{ background:'#1E293B', border:'0.5px solid #1E3A5F' }}>
        <div className="flex items-center justify-between">
          <p className="text-sm font-semibold" style={{ color:'#E2E8F0' }}>Add asset</p>
          <button onClick={onClose}><X className="h-4 w-4" style={{ color:'#475569' }} /></button>
        </div>
        <input placeholder="Asset name (e.g. Production API)" {...inp('name')} />
        <input placeholder="Target (e.g. api.example.com)" {...inp('target')} />
        <div className="grid grid-cols-2 gap-3">
          <select {...inp('asset_type')}>
            {['domain','ip','cidr','url'].map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
          </select>
          <select {...inp('risk_tier')}>
            {['critical','high','medium','low'].map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <input placeholder="Owner (optional)" {...inp('owner')} />
        <input placeholder="Tags (comma-separated)" {...inp('tags')} />
        <div className="flex gap-2 pt-2">
          <button onClick={() => create.mutate()} disabled={!form.name || !form.target || create.isPending}
            className="flex-1 rounded-lg py-2 text-sm font-medium transition-colors disabled:opacity-40"
            style={{ background:'#1D4ED8', color:'#EFF6FF' }}>
            {create.isPending ? 'Adding...' : 'Add asset'}
          </button>
          <button onClick={onClose} className="rounded-lg px-4 py-2 text-sm"
            style={{ color:'#64748B' }}>Cancel</button>
        </div>
      </div>
    </div>
  )
}

export default function AssetsPage() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)

  const { data: assets, isLoading } = useQuery({
    queryKey: ['assets'],
    queryFn: () => api.get('/api/assets').then(r => r.data),
  })

  const quickScan = useMutation({
    mutationFn: (assetId: string) => api.post(`/api/assets/${assetId}/scan`),
    onSuccess: (_, assetId) => {
      toast.success('Scan launched')
      qc.invalidateQueries({ queryKey: ['assets'] })
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Failed to launch scan'),
  })

  return (
    <div className="space-y-5 animate-fade-in">
      {showModal && <NewAssetModal onClose={() => setShowModal(false)} />}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color:'#E2E8F0' }}>
            <FolderOpen className="h-5 w-5" style={{ color:'#60A5FA' }} /> Assets
          </h1>
          <p className="text-sm mt-0.5" style={{ color:'#64748B' }}>
            {(assets ?? []).length} targets in inventory
          </p>
        </div>
        <button onClick={() => setShowModal(true)}
          className="flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium"
          style={{ background:'#1D4ED8', color:'#EFF6FF' }}>
          <Plus className="h-4 w-4" /> Add asset
        </button>
      </div>

      <div className="rounded-lg overflow-hidden" style={{ border:'0.5px solid #1E3A5F' }}>
        <div className="grid grid-cols-12 gap-4 px-4 py-2 text-xs font-medium"
          style={{ background:'#0C1628', color:'#475569' }}>
          <div className="col-span-4">Asset</div>
          <div className="col-span-2">Risk tier</div>
          <div className="col-span-2">Risk score</div>
          <div className="col-span-2">Last scan</div>
          <div className="col-span-2" />
        </div>

        {isLoading ? (
          Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-16 animate-pulse"
              style={{ background:'#1E293B', borderTop:'0.5px solid #1E3A5F' }} />
          ))
        ) : (assets ?? []).length === 0 ? (
          <div className="flex flex-col items-center py-16 gap-3" style={{ background:'#1E293B' }}>
            <FolderOpen className="h-10 w-10" style={{ color:'#334155' }} />
            <p className="text-sm" style={{ color:'#475569' }}>No assets yet</p>
            <button onClick={() => setShowModal(true)}
              className="text-xs px-3 py-1.5 rounded-md"
              style={{ background:'#1D4ED8', color:'#EFF6FF' }}>
              Add first asset
            </button>
          </div>
        ) : (
          (assets ?? []).map((a: any, i: number) => (
            <div key={a.id}
              className="grid grid-cols-12 gap-4 px-4 py-3 items-center"
              style={{ background:'#1E293B', borderTop:'0.5px solid #1E3A5F' }}>
              <div className="col-span-4 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm">{TYPE_ICON[a.asset_type] ?? '🔗'}</span>
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate" style={{ color:'#E2E8F0' }}>{a.name}</p>
                    <p className="text-xs truncate" style={{ color:'#475569' }}>{a.target}</p>
                  </div>
                </div>
              </div>
              <div className="col-span-2">
                <span className="text-xs rounded-full px-2 py-0.5 capitalize"
                  style={{ background:`${RISK_COLOR[a.risk_tier]}22`, color:RISK_COLOR[a.risk_tier] ?? '#94A3B8' }}>
                  {a.risk_tier}
                </span>
              </div>
              <div className="col-span-2">
                {a.risk_score > 0 ? (
                  <span className="text-sm font-bold" style={{ color:riskColor(a.risk_score) }}>
                    {Math.round(a.risk_score)}
                  </span>
                ) : <span style={{ color:'#334155' }}>—</span>}
              </div>
              <div className="col-span-2">
                <span className="text-xs" style={{ color:'#475569' }}>
                  {a.last_scan_at ? formatRelative(a.last_scan_at) : 'Never'}
                </span>
              </div>
              <div className="col-span-2 flex justify-end gap-2">
                <button
                  onClick={() => quickScan.mutate(a.id)}
                  disabled={quickScan.isPending}
                  className="flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs transition-colors"
                  style={{ background:'#1D4ED820', color:'#60A5FA', border:'0.5px solid #1D4ED855' }}>
                  <Radar className="h-3 w-3" /> Scan
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
