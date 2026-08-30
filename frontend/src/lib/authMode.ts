// Which authentication mode the platform runs in. Set at build time via
// NEXT_PUBLIC_AUTH_MODE so the UI renders the right sign-in flow and never
// initialises Clerk when Clerk isn't the active provider.
//
//   local — built-in email/password (default for self-hosting)
//   oidc  — external OIDC provider (login handled outside the SPA)
//   clerk — Clerk-hosted auth
export type AuthMode = 'local' | 'oidc' | 'clerk'

export const AUTH_MODE: AuthMode =
  (process.env.NEXT_PUBLIC_AUTH_MODE as AuthMode) || 'local'

export const isClerk = AUTH_MODE === 'clerk'
export const isLocal = AUTH_MODE === 'local'
