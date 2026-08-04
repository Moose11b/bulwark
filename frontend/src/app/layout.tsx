import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { ClerkProvider } from '@clerk/nextjs'
import { Providers } from '@/components/providers'
import { Toaster } from 'sonner'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: { default: 'Bulwark', template: '%s — Bulwark' },
  description: 'Fortify · Detect · Defend',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <ClerkProvider>
      <html lang="en" className="dark" suppressHydrationWarning>
        <body className={`${inter.className} min-h-screen bg-background antialiased`}>
          <Providers>
            {children}
            <Toaster position="bottom-right" richColors />
          </Providers>
        </body>
      </html>
    </ClerkProvider>
  )
}
