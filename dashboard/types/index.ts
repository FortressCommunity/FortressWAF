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
