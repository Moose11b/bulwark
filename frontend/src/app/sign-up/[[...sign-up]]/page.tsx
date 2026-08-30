import Link from 'next/link'
import { SignUp } from '@clerk/nextjs'
import { isClerk } from '@/lib/authMode'

export default function SignUpPage() {
  return (
    <div className="flex min-h-screen items-center justify-center"
      style={{ background: '#0C1628' }}>
      {isClerk ? (
        <SignUp />
      ) : (
        // Local mode has no public sign-up — accounts are created by an admin.
        <div style={{ width: 360, textAlign: 'center', color: '#94A3B8' }}>
          <h1 style={{ color: '#E2E8F0', fontSize: 18, fontWeight: 700, marginBottom: 8 }}>
            Accounts are created by an administrator
          </h1>
          <p style={{ fontSize: 14, marginBottom: 20 }}>
            Ask your Bulwark admin to create an account for you, then sign in.
          </p>
          <Link href="/sign-in" style={{ color: '#60A5FA', fontSize: 14 }}>
            Back to sign in
          </Link>
        </div>
      )}
    </div>
  )
}
