import type { Analysis, Health } from './types'

/** Production API — baked in, no .env */
const BASE = 'https://api2.mpnetwork.space'
export const API_BASE = BASE

async function parse<T>(res: Response): Promise<T> {
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || `HTTP ${res.status}`)
  }
  return data as T
}

export async function fetchHealth(): Promise<Health> {
  const res = await fetch(`${BASE}/api/health`)
  return parse(res)
}

export async function uploadPcap(file: File): Promise<Analysis> {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`${BASE}/api/analyze`, { method: 'POST', body: form })
  return parse(res)
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}
