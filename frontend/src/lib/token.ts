// Local-auth session token storage. Kept in its own module (imported by both
// the axios client and the auth client) to avoid an import cycle. All access
// is guarded so it is safe during SSR and when storage is unavailable.
const TOKEN_KEY = 'bulwark_token'

export function getStoredToken(): string | null {
  if (typeof window === 'undefined') return null
  try {
    return window.localStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function setStoredToken(token: string): void {
  try {
    window.localStorage.setItem(TOKEN_KEY, token)
  } catch {
    /* storage unavailable — the session simply won't persist */
  }
}

export function clearStoredToken(): void {
  try {
    window.localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* ignore */
  }
}
