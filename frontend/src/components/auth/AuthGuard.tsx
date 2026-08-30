'use client'
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { isAuthed } from '@/lib/authClient'

// Client-side route guard for local/OIDC mode, where the server can't read the
// browser-held token. The API is always the real authority — it rejects any
// request without a valid token — so this only decides whether to render the
// dashboard shell or bounce to the sign-in page.
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const [ok, setOk] = useState(false)

  useEffect(() => {
    if (isAuthed()) {
      setOk(true)
    } else {
      router.replace('/sign-in')
    }
  }, [router])

  if (!ok) return null
  return <>{children}</>
}
