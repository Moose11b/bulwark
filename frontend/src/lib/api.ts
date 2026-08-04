import axios from 'axios'

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  headers: { 'Content-Type': 'application/json' },
})

// Race a promise against a timeout — protects us from Clerk's getToken()
// occasionally hanging (which would block every API request indefinitely).
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T | null> {
  return Promise.race([
    promise,
    new Promise<null>(resolve => setTimeout(() => resolve(null), ms)),
  ])
}

api.interceptors.request.use(async (config) => {
  if (typeof window !== 'undefined') {
    try {
      const clerk = (window as any).Clerk
      if (clerk?.session) {
        const token = await withTimeout(clerk.session.getToken(), 3000)
        if (token) {
          config.headers.Authorization = `Bearer ${token}`
        } else {
          // Token fetch hung or returned nothing — fire the request anyway.
          // Backend will return 401 if auth is required, surfacing the issue
          // instead of leaving the user staring at a frozen Launching button.
          console.warn('[api] Clerk token unavailable, sending request unauthenticated')
        }
      }
    } catch (err) {
      console.warn('[api] Token interceptor error:', err)
    }
  }
  return config
})

export default api
export { api }
