'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { toast } from 'sonner'
import { localChangePassword, localLogin } from '@/lib/authClient'

// Built-in email/password sign-in. Two steps: log in, and — when the account
// was flagged (e.g. the first-run admin) — force a password change before
// entering the dashboard.
export function LocalSignIn() {
  const router = useRouter()
  const [step, setStep] = useState<'login' | 'change'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)

  async function onLogin(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    try {
      const res = await localLogin(email, password)
      if (res.must_change_password) {
        setStep('change')
      } else {
        router.push('/dashboard')
      }
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Incorrect email or password')
    } finally {
      setBusy(false)
    }
  }

  async function onChange(e: React.FormEvent) {
    e.preventDefault()
    if (newPassword !== confirm) {
      toast.error('Passwords do not match')
      return
    }
    setBusy(true)
    try {
      await localChangePassword(password, newPassword)
      toast.success('Password updated')
      router.push('/dashboard')
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Could not change password')
    } finally {
      setBusy(false)
    }
  }

  const field: React.CSSProperties = {
    width: '100%', padding: '10px 12px', marginTop: 6, marginBottom: 14,
    borderRadius: 8, border: '1px solid #1E293B', background: '#0B1220',
    color: '#E2E8F0', fontSize: 14,
  }
  const label: React.CSSProperties = { color: '#94A3B8', fontSize: 13 }
  const button: React.CSSProperties = {
    width: '100%', padding: '11px 12px', borderRadius: 8, border: 'none',
    background: busy ? '#1E3A8A' : '#1D4ED8', color: 'white', fontWeight: 600,
    fontSize: 14, cursor: busy ? 'default' : 'pointer',
  }

  return (
    <div style={{ width: 360, background: '#0F172A', border: '1px solid #1E293B',
                  borderRadius: 12, padding: 28 }}>
      {step === 'login' ? (
        <form onSubmit={onLogin}>
          <h1 style={{ color: '#E2E8F0', fontSize: 18, fontWeight: 700, marginBottom: 4 }}>
            Sign in
          </h1>
          <p style={{ color: '#64748B', fontSize: 13, marginBottom: 20 }}>
            Use your Bulwark account.
          </p>
          <label style={label}>Email</label>
          <input style={field} type="email" autoComplete="username" required
                 value={email} onChange={(e) => setEmail(e.target.value)} />
          <label style={label}>Password</label>
          <input style={field} type="password" autoComplete="current-password" required
                 value={password} onChange={(e) => setPassword(e.target.value)} />
          <button style={button} type="submit" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      ) : (
        <form onSubmit={onChange}>
          <h1 style={{ color: '#E2E8F0', fontSize: 18, fontWeight: 700, marginBottom: 4 }}>
            Set a new password
          </h1>
          <p style={{ color: '#64748B', fontSize: 13, marginBottom: 20 }}>
            Choose a password to finish setting up your account.
          </p>
          <label style={label}>New password</label>
          <input style={field} type="password" autoComplete="new-password" required
                 value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
          <label style={label}>Confirm password</label>
          <input style={field} type="password" autoComplete="new-password" required
                 value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          <button style={button} type="submit" disabled={busy}>
            {busy ? 'Saving…' : 'Save and continue'}
          </button>
        </form>
      )}
    </div>
  )
}
