'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { toast } from 'sonner'
import { Clock, Plus, ToggleLeft, ToggleRight, Trash2 } from 'lucide-react'

export default function SchedulesPage() {
  const qc = useQueryClient()
  const [show, setShow] = useState(false)
  const [form, setForm] = useState({ asset_id: '', scan_type: 'full', cron_expression: '0 2 * * 1' })
  const { data: schedules } = useQuery({ queryKey: ['schedules'], queryFn: () => api.get('/api/schedules').then(r => r.data) })
  const { data: assets } = useQuery({ queryKey: ['assets'], queryFn: () => api.get('/api/assets').then(r => r.data) })
  const create = useMutation({ mutationFn: () => api.post('/api/schedules', form), onSuccess: () => { toast.success('Schedule created'); qc.invalidateQueries({ queryKey: ['schedules'] }); setShow(false) }, onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Failed') })
  const toggle = useMutation({ mutationFn: (id: string) => api.patch(`/api/schedules/${id}/toggle`), onSuccess: () => qc.invalidateQueries({ queryKey: ['schedules'] }) })
  const del = useMutation({ mutationFn: (id: string) => api.delete(`/api/schedules/${id}`), onSuccess: () => { toast.success('Deleted'); qc.invalidateQueries({ queryKey: ['schedules'] }) } })
  return (
    <div className="space-y-5 animate-fade-in max-w-2xl">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: '#E2E8F0' }}><Clock className="h-5 w-5" style={{ color: '#FDBA74' }} /> Schedules</h1>
        <button onClick={() => setShow(v => !v)} className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium" style={{ background: '#1D4ED8', color: '#EFF6FF' }}><Plus className="h-4 w-4" /> New</button>
      </div>
      {show && (
        <div className="rounded-lg p-4 space-y-3" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
          <select value={form.asset_id} onChange={e => setForm(f => ({ ...f, asset_id: e.target.value }))} className="w-full rounded-lg px-3 py-2 text-sm outline-none" style={{ background: '#0F172A', border: '0.5px solid #1E3A5F', color: '#E2E8F0' }}>
            <option value="">Select asset</option>
            {(assets ?? []).map((a: any) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
          <div className="flex gap-2">
            {[{ l: 'Daily', c: '0 2 * * *' }, { l: 'Weekly', c: '0 2 * * 1' }, { l: 'Monthly', c: '0 2 1 * *' }].map(p => (
              <button key={p.c} onClick={() => setForm(f => ({ ...f, cron_expression: p.c }))} className="text-xs rounded-md px-2.5 py-1" style={{ background: form.cron_expression === p.c ? '#1D4ED820' : '#0F172A', color: form.cron_expression === p.c ? '#60A5FA' : '#64748B', border: `0.5px solid ${form.cron_expression === p.c ? '#1D4ED855' : '#1E3A5F'}` }}>{p.l}</button>
            ))}
          </div>
          <div className="flex gap-2">
            <button onClick={() => create.mutate()} disabled={!form.asset_id || create.isPending} className="rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-40" style={{ background: '#1D4ED8', color: '#EFF6FF' }}>Create</button>
            <button onClick={() => setShow(false)} className="rounded-lg px-4 py-2 text-sm" style={{ color: '#64748B' }}>Cancel</button>
          </div>
        </div>
      )}
      <div className="space-y-2">
        {(schedules ?? []).length === 0 && <div className="flex h-32 items-center justify-center rounded-lg" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}><p className="text-sm" style={{ color: '#475569' }}>No schedules yet</p></div>}
        {(schedules ?? []).map((s: any) => (
          <div key={s.id} className="flex items-center gap-3 rounded-lg px-4 py-3" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
            <div className="flex-1"><p className="text-sm" style={{ color: '#E2E8F0' }}>{(assets ?? []).find((a: any) => a.id === s.asset_id)?.name ?? 'Asset'}</p><p className="text-xs" style={{ color: '#475569' }}>{s.scan_type?.toUpperCase()} · {s.cron_expression}</p></div>
            <button onClick={() => toggle.mutate(s.id)}>{s.is_active ? <ToggleRight className="h-5 w-5" style={{ color: '#86EFAC' }} /> : <ToggleLeft className="h-5 w-5" style={{ color: '#334155' }} />}</button>
            <button onClick={() => del.mutate(s.id)}><Trash2 className="h-4 w-4" style={{ color: '#334155' }} /></button>
          </div>
        ))}
      </div>
    </div>
  )
}
