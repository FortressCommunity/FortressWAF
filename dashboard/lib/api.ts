import type {
  LoginResponse, User, Status, AuditResponse, SitesResponse,
  InspectorsResponse, InspectorDetail, RulesResponse, ConfigSummary,
  ComplianceFrameworksResponse, ComplianceAssessment,
  MetricsSnapshot, AnalyticsResponse, TrafficResponse, AlertsResponse, Alert, ConfigDetail,
  DomainsResponse, ManagedDomain, BansResponse, Ban, TrainingStatus, DomainAddError,
} from '@/types'

// The admin API base. It defaults to a same-origin relative path, so the
// browser talks to whatever host it loaded the dashboard from — no separate
// API hostname to resolve, and no cross-origin hop that can fail on its own.
// Caddy serves /api/* on the dashboard host and forwards it to the WAF.
const API_BASE = process.env.NEXT_PUBLIC_API_URL || '/api/v1'

// The admin bearer token is persisted in sessionStorage, not localStorage:
// it is scoped to the tab and discarded when the tab closes, so a shared
// exhibition machine does not retain an admin session between visitors.
//
// It is still readable by JavaScript, so the real control against token theft
// is the strict Content-Security-Policy in next.config.mjs (no remote script
// origins), which removes the XSS path that would let an injected script read
// it. A future improvement is an httpOnly session cookie issued by the admin
// API, which would put the token out of JavaScript's reach entirely.
const TOKEN_KEY = 'fortresswaf_token'

// Storage access can THROW, not just return null: some Android browsers and
// any private/strict mode deny sessionStorage entirely and raise on access.
// An unguarded read at module load crashed the whole dashboard route (the
// login page never touched storage, so it still worked — which is exactly the
// "/ works, /dashboard doesn't" symptom). Every access is wrapped so a blocked
// store degrades to an in-memory token instead of taking the page down.
function safeGet(key: string): string | null {
  try {
    if (typeof window === 'undefined') return null
    return window.sessionStorage.getItem(key)
  } catch {
    return null
  }
}

function safeSet(key: string, value: string | null) {
  try {
    if (typeof window === 'undefined') return
    if (value === null) window.sessionStorage.removeItem(key)
    else window.sessionStorage.setItem(key, value)
  } catch {
    // Storage unavailable; the in-memory token still works for this tab.
  }
}

let authToken: string | null = safeGet(TOKEN_KEY)

export function setToken(token: string | null) {
  authToken = token
  safeSet(TOKEN_KEY, token)
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
  reloadConfig: () => request<{ status: string }>('/reload', { method: 'POST' }),

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

  metrics: () => request<MetricsSnapshot>('/metrics/snapshot'),
  analytics: () => request<AnalyticsResponse>('/analytics'),
  configDetail: () => request<ConfigDetail>('/config/detail'),

  traffic: (params?: { q?: string; action?: string; limit?: number }) => {
    const qs = new URLSearchParams()
    if (params?.q) qs.set('q', params.q)
    if (params?.action) qs.set('action', params.action)
    if (params?.limit) qs.set('limit', String(params.limit))
    const suffix = qs.toString() ? `?${qs.toString()}` : ''
    return request<TrafficResponse>(`/traffic${suffix}`)
  },

  inspector: (name: string) =>
    request<InspectorDetail>(`/inspectors/${encodeURIComponent(name)}`),

  alerts: {
    list: () => request<AlertsResponse>('/alerts'),
    create: (a: { severity: string; title: string; detail?: string; source?: string }) =>
      request<Alert>('/alerts', { method: 'POST', body: JSON.stringify(a) }),
    ack: (id: string) => request<{ status: string }>(`/alerts/${id}/ack`, { method: 'POST' }),
    remove: (id: string) => request<{ status: string }>(`/alerts/${id}`, { method: 'DELETE' }),
  },

  domains: {
    list: () => request<DomainsResponse>('/domains'),
    add: (d: { domain: string; site?: string; upstream?: string }) =>
      request<ManagedDomain>('/domains', { method: 'POST', body: JSON.stringify(d) }),
    remove: (domain: string) =>
      request<{ status: string }>(`/domains/${encodeURIComponent(domain)}`, { method: 'DELETE' }),
    verify: (domain: string) =>
      request<{ verified: boolean; resolved_ips: string[]; reason: string }>(
        `/domains/${encodeURIComponent(domain)}/verify`,
        { method: 'POST' },
      ),
  },

  bans: {
    list: () => request<BansResponse>('/bans'),
    add: (b: { ip: string; reason?: string; ttl_seconds?: number }) =>
      request<Ban>('/bans', { method: 'POST', body: JSON.stringify(b) }),
    remove: (ip: string) =>
      request<{ status: string }>(`/bans/${encodeURIComponent(ip)}`, { method: 'DELETE' }),
  },

  trainingStatus: () => request<TrainingStatus>('/training/status'),
}

export type { DomainAddError }
