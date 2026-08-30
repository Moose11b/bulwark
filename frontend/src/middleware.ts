import { NextResponse } from 'next/server'
import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server'
import { AUTH_MODE } from '@/lib/authMode'

// Route protection depends on the auth mode. Under Clerk, the middleware
// enforces auth server-side. Under local/OIDC, the browser holds the session
// token (unreadable here), so gating happens client-side via <AuthGuard/>, and
// the middleware is a passthrough. AUTH_MODE is inlined at build time, so the
// unused branch is eliminated and Clerk is never invoked when it isn't active.
const isPublicRoute = createRouteMatcher([
  '/sign-in(.*)',
  '/sign-up(.*)',
  '/api/webhooks(.*)',
])

const middleware =
  AUTH_MODE === 'clerk'
    ? clerkMiddleware(async (auth, request) => {
        if (!isPublicRoute(request)) {
          await auth.protect()
        }
      })
    : () => NextResponse.next()

export default middleware

export const config = {
  matcher: [
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    '/(api|trpc)(.*)',
  ],
}
