import * as React from 'react'
import { cn } from '@/lib/utils'

// Severity is derived from the rule-id prefix because that is what the engine
// records in the audit metadata. Keeping the mapping in one place means the
// traffic, alerts, and analytics pages colour the same rule the same way.
export type Severity = 'critical' | 'high' | 'medium' | 'low'

const PREFIX_SEVERITY: Array<[string, Severity]> = [
  ['SQLI', 'critical'],
  ['XSS', 'critical'],
  ['RCE', 'critical'],
  ['LEAK', 'critical'],
  ['PARSER_', 'high'],
  ['DSYNC', 'high'],
  ['API', 'high'],
  ['CRED', 'high'],
  ['PROT', 'medium'],
  ['UPL', 'medium'],
  ['BOT', 'medium'],
  ['JA3', 'low'],
]

export function severityForRule(ruleID: string): Severity {
  for (const [prefix, sev] of PREFIX_SEVERITY) {
    if (ruleID.startsWith(prefix)) return sev
  }
  return 'medium'
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: 'border-destructive/50 text-destructive bg-destructive/5',
  high: 'border-warning/50 text-warning bg-warning/5',
  medium: 'border-primary/40 text-primary bg-primary/5',
  low: 'border-border text-muted-foreground bg-muted/40',
}

const SEVERITY_DOT: Record<Severity, string> = {
  critical: 'bg-destructive',
  high: 'bg-warning',
  medium: 'bg-primary',
  low: 'bg-muted-foreground',
}

// SeverityTag is an outline chip, not a filled pill: the dashboard stays
// neutral and only the text carries the semantic colour.
export function SeverityTag({ ruleID, className }: { ruleID: string; className?: string }) {
  const sev = severityForRule(ruleID)
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-control border px-1.5 py-0.5 font-mono text-[11px] font-medium',
        SEVERITY_STYLE[sev],
        className,
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', SEVERITY_DOT[sev])} />
      {ruleID || 'unknown'}
    </span>
  )
}

export function SeverityDot({ severity }: { severity: Severity }) {
  return <span className={cn('inline-block h-2 w-2 shrink-0 rounded-full', SEVERITY_DOT[severity])} />
}

// A labelled metric line used in dense headers.
export function MetaItem({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">{label}</span>
      <span className={cn('text-sm text-foreground', mono && 'font-mono tabular-nums')}>{value}</span>
    </div>
  )
}
