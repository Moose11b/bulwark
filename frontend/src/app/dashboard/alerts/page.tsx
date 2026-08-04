'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { toast } from 'sonner'
import { Bell, Plus, ToggleLeft, ToggleRight, Trash2 } from 'lucide-react'

export default function AlertsPage() {
  const qc = useQueryClient()
  const [show, setShow] = useState(false)
  const [form, setForm] = useState({ name: '', channel: 'slack', webhook_url: '', email_to: '', min_severity: 'HIGH' })
  const { data: configs } = useQuery({ queryKey: ['alerts'], queryFn: () => api.get('/api/alerts').then(r => r.data) })
  const create = useMutation({ mutationFn: () => api.post('/api/alerts', form), onSuccess: () => { toast.success('Alert created'); qc.invalidateQueries({ queryKey: ['alerts'] }); setShow(false) }, onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Failed') })
  const toggle = useMutation({ mutationFn: (id: string) => api.patch(`/api/alerts/${id}/toggle`), onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }) })
  const del = useMutation({ mutationFn: (id: string) => api.delete(`/api/alerts/${id}`), onSuccess: () => { toast.success('Deleted'); qc.invalidateQueries({ queryKey: ['alerts'] }) } })
  const i = (f: string) => ({ value: (form as any)[f], onChange: (e: any) => setForm(v => ({ ...v, [f]: e.target.value })), className: 'w-full rounded-lg px-3 py-2 text-sm outline-none', style: { background: '#0F172A', border: '0.5px solid #1E3A5F', color: '#E2E8F0' } as any })
  return (
    <div className="space-y-5 animate-fade-in max-w-2xl">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: '#E2E8F0' }}><Bell className="h-5 w-5" style={{ color: '#93C5FD' }} /> Alerts</h1>
        <button onClick={() => setShow(v => !v)} className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium" style={{ background: '#1D4ED8', color: '#EFF6FF' }}><Plus className="h-4 w-4" /> Add</button>
      </div>
      {show && (
        <div className="rounded-lg p-4 space-y-3" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
          <input placeholder="Alert name" {...i('name')} />
          <div className="grid grid-cols-2 gap-3">
            <select {...i('channel')}><option value="slack">Slack</option><option value="email">Email</option></select>
            <select {...i('min_severity')}>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{s}</option>)}</select>
          </div>
          {form.channel === 'slack' ? <input placeholder="Slack webhook URL" {...i('webhook_url')} /> : <input placeholder="Email address" {...i('email_to')} />}
          <div className="flex gap-2">
            <button onClick={() => create.mutate()} disabled={!form.name || create.isPending} className="rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-40" style={{ background: '#1D4ED8', color: '#EFF6FF' }}>Create</button>
            <button onClick={() => setShow(false)} className="rounded-lg px-4 py-2 text-sm" style={{ color: '#64748B' }}>Cancel</button>
          </div>
        </div>
      )}
      <div className="space-y-2">
        {(configs ?? []).length === 0 && <div className="flex h-32 items-center justify-center rounded-lg" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}><p className="text-sm" style={{ color: '#475569' }}>No alerts configured</p></div>}
        {(configs ?? []).map((c: any) => (
          <div key={c.id} className="flex items-center gap-3 rounded-lg px-4 py-3" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
            <Bell className="h-4 w-4 shrink-0" style={{ color: c.is_active ? '#86EFAC' : '#334155' }} />
            <div className="flex-1"><p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>{c.name}</p><p className="text-xs" style={{ color: '#475569' }}>{c.channel} · {c.min_severity}+</p></div>
            <button onClick={() => toggle.mutate(c.id)}>{c.is_active ? <ToggleRight className="h-5 w-5" style={{ color: '#86EFAC' }} /> : <ToggleLeft className="h-5 w-5" style={{ color: '#334155' }} />}</button>
            <button onClick={() => del.mutate(c.id)}><Trash2 className="h-4 w-4" style={{ color: '#334155' }} /></button>
          </div>
        ))}
      </div>
    </div>
  )
}
