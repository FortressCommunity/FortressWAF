// Response shapes for the admin API. Every type here mirrors a JSON object
// the Go server actually emits -- nothing is speculative.

export interface User {
  id: string
  email: string
  name: string
  role: string
}

export interface LoginResponse {
  token: string
  user: User
}

// GET /api/v1/status
export interface Status {
  version: string
  commit: string
  build_date: string
  uptime: string
  uptime_seconds: number
  requests_per_sec: number
  total_requests: number
  blocked_requests: number
  allowed_requests: number
  active_connections: number
  challenged: number
  rate_limited: number
  monitored: number
}

// GET /api/v1/audit
export interface AuditEntry {
  id: string
  timestamp: string
  actor_id: string
  actor_type: string
  actor_ip: string
  action: string
  resource: string
  resource_id: string
  result: string
  metadata: string
  hash: string
  prev_hash: string
  // Request forensics, present on entries written by the request path.
  method?: string
  path?: string
  status_code?: number
  user_agent?: string
  browser?: string
  device?: string
  headers?: Record<string, string>
}

export interface AuditResponse {
  total: number
  entries: AuditEntry[]
  integrity: {
    valid: boolean
    error: string | null
  }
}

// GET /api/v1/sites
export interface Site {
  name: string
  domains: string[]
  upstream: string
  port: number
  tls: boolean
  waf_enabled: boolean
}

export interface SitesResponse {
  sites: Site[]
  count: number
}

// GET /api/v1/inspectors
export interface Inspector {
  name: string
  enabled: boolean
  hits: number
}

export interface InspectorsResponse {
  inspectors: Inspector[]
  count: number
}

// GET /api/v1/rules (rules defined in the config file)
export interface ConfigRule {
  id: string
  name: string
  description: string
  enabled: boolean
  severity: string
  action: string
  tags: string[]
}

export interface RulesResponse {
  rules: ConfigRule[]
  count: number
}

// GET /api/v1/config
export interface ConfigSummary {
  sites_count: number
  rules_count: number
  ml_enabled: boolean
  redis_enabled: boolean
  admin_port: number
  sites: Array<{
    name: string
    domains: string[]
    upstream: string
    waf_enabled: boolean
  }>
}

// GET /api/v1/compliance/frameworks
export interface ComplianceFramework {
  id: string
  description: string
  total: number
  automated: number
  manual: number
  controls: number
  compliant: number
  compliant_percent: number
}

export interface ComplianceFrameworksResponse {
  frameworks: ComplianceFramework[]
}

// GET /api/v1/compliance/{framework}/assessment
export interface Evidence {
  type: string
  description: string
}

export interface ComplianceControl {
  id: string
  framework: string
  name: string
  description: string
  status: string
  last_checked: string
  evidence: Evidence[] | null
  remediation: string
}

export interface ComplianceAssessment {
  framework: string
  assessed_at: string
  compliant_count: number
  manual_count: number
  total_count: number
  automated_controls: number
  compliance_percent: number
  controls: ComplianceControl[]
}

// GET /api/v1/metrics/snapshot
export interface MetricsSnapshot {
  uptime_seconds: number
  requests_total: number
  requests_blocked: number
  requests_allowed: number
  requests_excluded: number
  requests_challenged: number
  requests_rate_limited: number
  requests_monitored: number
  active_connections: number
  requests_per_second: number
  block_rate_percent: number
}

// GET /api/v1/analytics
export interface AnalyticsSeriesPoint {
  minute: string
  count: number
}

export interface AnalyticsCount {
  count: number
}

export interface AnalyticsResponse {
  total_events: number
  series: AnalyticsSeriesPoint[]
  top_attackers: Array<{ ip: string; count: number }>
  top_rules: Array<{ rule: string; count: number }>
  by_action: Array<{ action: string; count: number }>
  by_result: Array<{ result: string; count: number }>
}

// GET /api/v1/traffic
export interface TrafficResponse {
  total: number
  count: number
  entries: AuditEntry[]
}

// GET /api/v1/alerts
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface Alert {
  id: string
  created_at: string
  severity: AlertSeverity
  title: string
  detail: string
  source: string
  acknowledged: boolean
  acked_by?: string
  acked_at?: string
}

export interface AlertsResponse {
  total: number
  unacked: number
  by_severity: Record<string, number>
  alerts: Alert[]
}

// GET /api/v1/config/detail
export interface ConfigDetail {
  version: string
  commit: string
  build_date: string
  sites_count: number
  rules_count: number
  enabled_modules: string[]
  modules: Record<string, boolean>
  response_inspect_blocks: boolean
  tls_enabled: boolean
  shadow_mode: boolean
  learning_mode: boolean
  prometheus: boolean
}

// GET /api/v1/inspectors/{name}
export interface InspectorDetail {
  name: string
  rule_prefix: string
  hits: number
  recent: AuditEntry[]
}

// GET /api/v1/domains
export interface ManagedDomain {
  domain: string
  site: string
  upstream: string
  verified: boolean
  resolved_ips: string[] | null
  reason: string
  added_at: string
}

export interface DomainsResponse {
  domains: ManagedDomain[]
  expected_ips: string[] | null
  count: number
}

// POST /api/v1/domains (422 body)
export interface DomainAddError {
  error: string
  domain: string
  resolved_ips: string[] | null
  expected_ips: string[] | null
}

// GET /api/v1/bans
export interface Ban {
  ip: string
  reason: string
  created_at: string
  expires_at: string
  created_by: string
  permanent: boolean
}

export interface BansResponse {
  bans: Ban[]
  count: number
}

// GET /api/v1/training/status
export interface TrainingStatus {
  enabled: boolean
  corpus_dir: string
  collected?: number
  dropped?: number
  unique?: number
  corpus_sizes?: Record<string, number>
  note?: string
}
