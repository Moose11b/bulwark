import { SignIn } from '@clerk/nextjs'

export default function SignInPage() {
  return (
    <div className="flex min-h-screen items-center justify-center"
      style={{ background: '#0C1628' }}>
      <div className="mb-8 text-center absolute top-10">
        <div className="flex items-center justify-center gap-3 mb-2">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl"
            style={{ background: '#1D4ED8' }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z" fill="#EFF6FF"/>
              <path d="M9 12l2 2 4-4" stroke="#1D4ED8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <span style={{ color: '#E2E8F0', fontSize: '20px', fontWeight: 700, letterSpacing: '0.1em' }}>
            BULWARK
          </span>
        </div>
        <p style={{ color: '#475569', fontSize: '12px', letterSpacing: '0.1em' }}>
          FORTIFY · DETECT · DEFEND
        </p>
      </div>
      <SignIn />
    </div>
  )
}
