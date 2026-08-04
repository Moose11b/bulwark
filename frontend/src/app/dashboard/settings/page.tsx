'use client'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Settings, CreditCard, ExternalLink } from 'lucide-react'

const PC: Record<string, string> = { starter: '#60A5FA', pro: '#FDBA74', enterprise: '#C4B5FD' }

export default function SettingsPage() {
  const { data: me } = useQuery({ queryKey: ['me'], queryFn: () => api.get('/api/auth/me').then(r => r.data) })
  const { data: plans } = useQuery({ queryKey: ['plans'], queryFn: () => api.get('/api/billing/plans').then(r => r.data) })
  const openPortal = async () => { const r = await api.post('/api/billing/portal'); window.open(r.data.url, '_blank') }
  const openCheckout = async (pid: string) => { const r = await api.post('/api/billing/checkout', { price_id: pid, success_url: window.location.origin + '/dashboard/settings', cancel_url: window.location.origin + '/dashboard/settings' }); window.open(r.data.url, '_blank') }
  return (
    <div className="space-y-6 animate-fade-in max-w-2xl">
      <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: '#E2E8F0' }}><Settings className="h-5 w-5" style={{ color: '#94A3B8' }} /> Settings</h1>
      <div className="rounded-lg p-5 space-y-3" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
        <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>Account</p>
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-full flex items-center justify-center text-sm font-bold" style={{ background: '#1D4ED820', color: '#60A5FA' }}>{me?.name?.[0] ?? '?'}</div>
          <div><p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>{me?.name ?? '—'}</p><p className="text-xs" style={{ color: '#64748B' }}>{me?.email} · {me?.role}</p></div>
        </div>
      </div>
      {me?.org && (
        <div className="rounded-lg p-5 space-y-4" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>Plan</p>
            <span className="text-xs rounded-full px-2 py-0.5 capitalize font-medium" style={{ background: `${PC[me.org.plan] ?? '#60A5FA'}20`, color: PC[me.org.plan] ?? '#60A5FA' }}>{me.org.plan}</span>
          </div>
          <div className="flex items-center gap-4">
            <div><p className="text-2xl font-bold" style={{ color: '#E2E8F0' }}>{me.org.scan_count_month}</p><p className="text-xs" style={{ color: '#475569' }}>scans this month</p></div>
            <span style={{ color: '#334155' }}>/</span>
            <div><p className="text-2xl font-bold" style={{ color: '#94A3B8' }}>{me.org.scan_limit >= 99999 ? '∞' : me.org.scan_limit}</p><p className="text-xs" style={{ color: '#475569' }}>limit</p></div>
          </div>
          <div className="h-1.5 rounded-full overflow-hidden" style={{ background: '#0F172A' }}><div className="h-1.5 rounded-full" style={{ width: `${Math.min(me.org.scan_count_month / me.org.scan_limit * 100, 100)}%`, background: PC[me.org.plan] ?? '#60A5FA' }} /></div>
          <button onClick={openPortal} className="flex items-center gap-2 text-sm" style={{ color: '#60A5FA' }}><CreditCard className="h-4 w-4" /> Manage billing <ExternalLink className="h-3.5 w-3.5" /></button>
        </div>
      )}
      {plans && me?.org && (
        <div className="rounded-lg p-5 space-y-4" style={{ background: '#1E293B', border: '0.5px solid #1E3A5F' }}>
          <p className="text-sm font-medium" style={{ color: '#E2E8F0' }}>Upgrade</p>
          <div className="grid grid-cols-3 gap-3">
            {(plans ?? []).filter((p: any) => p.id !== me.org.plan).map((plan: any) => (
              <button key={plan.id} onClick={() => plan.price_id && openCheckout(plan.price_id)} className="rounded-lg p-3 text-left hover:bg-white/[.02]" style={{ background: '#0F172A', border: `0.5px solid ${PC[plan.id] ?? '#1E3A5F'}44` }}>
                <p className="text-sm font-semibold" style={{ color: PC[plan.id] ?? '#E2E8F0' }}>{plan.name}</p>
                <p className="text-base font-bold mt-1" style={{ color: '#E2E8F0' }}>{plan.price_monthly ? `$${plan.price_monthly}/mo` : 'Custom'}</p>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
