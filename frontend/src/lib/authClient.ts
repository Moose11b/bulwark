// Local (email/password) auth client. Talks to the backend's /api/auth
// endpoints and manages the stored session token. Only used when AUTH_MODE is
// 'local'; Clerk mode uses Clerk's own SDK.
import api from './api'
import { clearStoredToken, getStoredToken, setStoredToken } from './token'

export interface LocalUser {
  id: string
  email: string
  name: string | null
  role: string
}

export interface LoginResult {
  access_token: string
  must_change_password: boolean
  user: LocalUser
}

export async function localLogin(email: string, password: string): Promise<LoginResult> {
  const { data } = await api.post<LoginResult>('/api/auth/login', { email, password })
  setStoredToken(data.access_token)
  return data
}

export async function localChangePassword(
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  await api.post('/api/auth/change-password', {
    current_password: currentPassword,
    new_password: newPassword,
  })
}

export function localLogout(): void {
  clearStoredToken()
  if (typeof window !== 'undefined') window.location.href = '/sign-in'
}

export function isAuthed(): boolean {
  return !!getStoredToken()
}
