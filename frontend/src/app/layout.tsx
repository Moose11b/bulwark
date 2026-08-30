import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { ClerkProvider } from '@clerk/nextjs'
import { Providers } from '@/components/providers'
import { Toaster } from 'sonner'
import { isClerk } from '@/lib/authMode'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: { default: 'Bulwark', template: '%s — Bulwark' },
  description: 'Fortify · Detect · Defend',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const tree = (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className={`${inter.className} min-h-screen bg-background antialiased`}>
        <Providers>
          {children}
          <Toaster position="bottom-right" richColors />
        </Providers>
      </body>
    </html>
  )

  // Only mount ClerkProvider when Clerk is the active mode — it requires a
  // publishable key and would throw otherwise.
  return isClerk ? <ClerkProvider>{tree}</ClerkProvider> : tree
}
