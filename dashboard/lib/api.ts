import type {
  LoginResponse, User, Status, AuditResponse, SitesResponse,
  InspectorsResponse, RulesResponse, ConfigSummary,
  ComplianceFrameworksResponse, ComplianceAssessment,
} from '@/types'

// The admin API base. In the demo stack the dashboard container is built with
// NEXT_PUBLIC_API_URL pointing at the proxy's admin port.
const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8443/api/v1'

let authToken: string | null = null

if (typeof window !== 'undefined') {
  authToken = localStorage.getItem('fortresswaf_token')
}

export function setToken(token: string | null) {
  authToken = token
  if (typeof window !== 'undefined') {
    if (token) localStorage.setItem('fortresswaf_token', token)
    else localStorage.removeItem('fortresswaf_token')
  }
}

export function getToken(): string | null {
  return authToken
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  })

  if (response.status === 401) {
    setToken(null)
    if (typeof window !== 'undefined') {
      window.location.href = '/'
    }
    throw new ApiError(401, 'Session expired. Sign in again.')
  }

  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    const msg = (body as { error?: string; detail?: string; message?: string })
    throw new ApiError(
      response.status,
      msg.error || msg.detail || msg.message || response.statusText,
    )
  }

  if (response.status === 204) return undefined as T
  return response.json()
}

// Only endpoints the server actually serves are listed here. The previous
// version declared ~40 routes (analytics, patches, settings, tenants, SSO)
// for handlers that do not exist; calling them made every page fail.
export const api = {
  auth: {
    login: (email: string, password: string) =>
      request<LoginResponse>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      }),
    me: () => request<User>('/auth/me'),
  },

  status: () => request<Status>('/status'),
  config: () => request<ConfigSummary>('/config'),

  sites: () => request<SitesResponse>('/sites'),
  inspectors: () => request<InspectorsResponse>('/inspectors'),
  rules: () => request<RulesResponse>('/rules'),

  audit: (action?: string) =>
    request<AuditResponse>(
      `/audit${action ? `?action=${encodeURIComponent(action)}` : ''}`,
    ),

  compliance: {
    frameworks: () => request<ComplianceFrameworksResponse>('/compliance/frameworks'),
    assessment: (framework: string) =>
      request<ComplianceAssessment>(`/compliance/${framework}/assessment`),
  },
}
