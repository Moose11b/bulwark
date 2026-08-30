'use client'
import { useEffect, useState } from 'react'
import { LogOut } from 'lucide-react'
import { localLogout } from '@/lib/authClient'
import { api } from '@/lib/api'

// Local-mode replacement for Clerk's <UserButton/>: shows the signed-in user
// and a sign-out control.
export function UserMenu() {
  const [email, setEmail] = useState<string>('')

  useEffect(() => {
    api.get('/api/auth/me')
      .then((r) => setEmail(r.data?.user?.email || ''))
      .catch(() => {})
  }, [])

  return (
    <div className="flex items-center gap-2">
      <div className="flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold"
           style={{ background: '#1D4ED8', color: 'white' }}
           title={email}>
        {(email[0] || 'U').toUpperCase()}
      </div>
      <button
        onClick={localLogout}
        title="Sign out"
        className="flex h-8 w-8 items-center justify-center rounded-md"
        style={{ color: '#94A3B8' }}
      >
        <LogOut size={16} />
      </button>
    </div>
  )
}
