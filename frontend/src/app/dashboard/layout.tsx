import { auth } from '@clerk/nextjs/server'
import { redirect } from 'next/navigation'
import { Sidebar } from '@/components/layout/Sidebar'
import { TopBar } from '@/components/layout/TopBar'
import { AUTH_MODE } from '@/lib/authMode'
import { AuthGuard } from '@/components/auth/AuthGuard'

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  // Clerk gates server-side; local/OIDC gate client-side (the token lives in
  // the browser). Either way the API rejects unauthenticated requests, so this
  // only controls whether the shell renders.
  if (AUTH_MODE === 'clerk') {
    const { userId } = await auth()
    if (!userId) redirect('/sign-in')
  }

  const body = (
    <div className="flex h-screen overflow-hidden" style={{ background: '#0F172A' }}>
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <TopBar />
        <main
          className="flex-1 overflow-y-auto p-6"
          style={{ background: '#0F172A' }}
        >
          <div className="mx-auto max-w-7xl">
            {children}
          </div>
        </main>
      </div>
    </div>
  )

  return AUTH_MODE === 'clerk' ? body : <AuthGuard>{body}</AuthGuard>
}
