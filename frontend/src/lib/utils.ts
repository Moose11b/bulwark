import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(date: string | Date) {
  return new Date(date).toLocaleDateString('en-GB', {
    day: 'numeric', month: 'short', year: 'numeric',
  })
}

export function formatRelative(date: string | Date) {
  const diff = Date.now() - new Date(date).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  return `${days}d ago`
}

export function severityColor(severity: string): string {
  return { CRITICAL:'#FCA5A5', HIGH:'#FDBA74', MEDIUM:'#FDE68A', LOW:'#86EFAC', INFO:'#93C5FD', PASS:'#94A3B8' }[severity.toUpperCase()] ?? '#94A3B8'
}

export function riskColor(score: number): string {
  if (score >= 75) return '#FCA5A5'
  if (score >= 50) return '#FDBA74'
  if (score >= 25) return '#FDE68A'
  return '#86EFAC'
}
