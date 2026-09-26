'use client'

import * as React from 'react'
import { Shield, ShieldAlert, ShieldCheck, Activity, Zap, Clock } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ChartContainer } from '@/components/ui/chart'
import { Skeleton } from '@/components/ui/skeleton'
import { api, ApiError } from '@/lib/api'
import { formatNumber, formatDate } from '@/lib/utils'
import type { Status, AuditEntry, Inspector } from '@/types'

// One bar in the attacks-over-time chart: blocked requests bucketed by minute.
function bucketByMinute(entries: AuditEntry[], buckets = 30) {
  const now = Date.now()
  const counts = Array.from({ length: buckets }, (_, i) => {
    const start = now - (buckets - 1 - i) * 60_000
    return { ts: start, value: 0, label: '' }
  })

  for (const ent of entries) {
    const t = new Date(ent.timestamp).getTime()
    const idx = buckets - 1 - Math.floor((now - t) / 60_000)
    if (idx >= 0 && idx < buckets) counts[idx].value++
  }

  return counts.map((c) => ({
    value: c.value,
    label: new Date(c.ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
  }))
}

// Rule family ("SQLI016: ..." -> "SQLI") counted across the audit log.
function topRuleFamilies(entries: AuditEntry[], limit = 6) {
  const counts = new Map<string, number>()
  for (const ent of entries) {
    const ruleID = ent.metadata.split(':')[0].trim()
    if (ruleID) counts.set(ruleID, (counts.get(ruleID) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit)
}

function topAttackers(entries: AuditEntry[], limit = 6) {
  const counts = new Map<string, number>()
  for (const ent of entries) {
    const ip = ent.actor_ip || 'unknown'
    counts.set(ip, (counts.get(ip) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([ip, attacks]) => ({ ip, attacks }))
    .sort((a, b) => b.attacks - a.attacks)
    .slice(0, limit)
}

function severityFor(ruleID: string): string {
  if (ruleID.startsWith('SQLI') || ruleID.startsWith('XSS') || ruleID.startsWith('RCE')) return 'critical'
  if (ruleID.startsWith('BOT')) return 'medium'
  return 'high'
}

function StatCard({
  title, value, icon, hint,
}: {
  title: string
  value: string
  icon: React.ReactNode
  hint?: string
}) {
  return (
    <Card className="border-2 border-foreground shadow-brutal">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-xs font-black uppercase tracking-wide text-muted-foreground">
          {title}
        </CardTitle>
        <div className="text-primary">{icon}</div>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-black text-foreground tabular-nums">{value}</div>
        {hint && <p className="text-xs text-muted-foreground font-bold mt-1">{hint}</p>}
      </CardContent>
    </Card>
  )
}

function ErrorState({ error, onRetry }: { error: string; onRetry: () => void }) {
  return (
    <Card className="border-2 border-destructive shadow-brutal-sm">
      <CardContent className="flex flex-col items-center justify-center gap-3 py-12 text-center">
        <ShieldAlert className="w-10 h-10 text-destructive" />
        <div>
          <h3 className="font-black uppercase text-foreground">Could not reach the WAF</h3>
          <p className="text-sm text-muted-foreground font-medium mt-1 max-w-md">{error}</p>
        </div>
        <Button variant="outline" onClick={onRetry}>Try again</Button>
      </CardContent>
    </Card>
  )
}

function EmptyState() {
  return (
    <Card className="border-2 border-dashed border-foreground/40">
      <CardContent className="flex flex-col items-center justify-center gap-3 py-12 text-center">
        <ShieldCheck className="w-10 h-10 text-primary" />
        <div>
          <h3 className="font-black uppercase text-foreground">No attacks recorded yet</h3>
          <p className="text-sm text-muted-foreground font-medium mt-1 max-w-md">
            The audit log is empty. Send an attack payload through the proxy and it will
            appear here in real time.
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

export default function OverviewPage() {
  const [status, setStatus] = React.useState<Status | null>(null)
  const [entries, setEntries] = React.useState<AuditEntry[]>([])
  const [inspectors, setInspectors] = React.useState<Inspector[]>([])
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  const load = React.useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [st, audit, insp] = await Promise.all([
        api.status(),
        api.audit(),
        api.inspectors(),
      ])
      setStatus(st)
      setEntries(audit.entries)
      setInspectors(insp.inspectors)
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `${err.message} (HTTP ${err.status})`
          : err instanceof Error
            ? err.message
            : 'Unknown error',
      )
    } finally {
      setLoading(false)
    }
  }, [])

  React.useEffect(() => {
    load()
    // Refresh every 5s so a live demo updates without a manual reload.
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [load])

  if (error) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-black uppercase tracking-tight text-foreground">Overview</h1>
          <p className="text-sm text-muted-foreground font-bold">Live security posture</p>
        </div>
        <ErrorState error={error} onRetry={load} />
      </div>
    )
  }

  const recent = [...entries]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 12)

  const activeInspectors = inspectors.filter((i) => i.enabled)
  const series = bucketByMinute(entries)
  const families = topRuleFamilies(entries)
  const attackers = topAttackers(entries)
  const maxFamily = Math.max(1, ...families.map((f) => f.value))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black uppercase tracking-tight text-foreground">Overview</h1>
          <p className="text-sm text-muted-foreground font-bold">Live security posture</p>
        </div>
        <Badge variant="outline" className="border-2 border-foreground font-black uppercase">
          <span className="mr-1.5 inline-block h-2 w-2 bg-primary" />
          {loading ? 'syncing' : 'live'}
        </Badge>
      </div>

      {loading && !status ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-28 border-2 border-foreground/20" />
          ))}
        </div>
      ) : status ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            title="Total requests"
            value={formatNumber(status.total_requests)}
            icon={<Activity className="w-5 h-5" />}
            hint={`${status.requests_per_sec.toFixed(1)} req/s since start`}
          />
          <StatCard
            title="Blocked"
            value={formatNumber(status.blocked_requests)}
            icon={<ShieldAlert className="w-5 h-5" />}
            hint={`${status.monitored} monitored · ${status.challenged} challenged`}
          />
          <StatCard
            title="Allowed"
            value={formatNumber(status.allowed_requests)}
            icon={<ShieldCheck className="w-5 h-5" />}
            hint={`${status.rate_limited} rate-limited`}
          />
          <StatCard
            title="Uptime"
            value={status.uptime}
            icon={<Clock className="w-5 h-5" />}
            hint={`${status.active_connections} active connections`}
          />
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ChartContainer
          title="Blocked attacks"
          subtitle="Requests blocked per minute, from the audit log"
          className="lg:col-span-2"
        >
          {entries.length === 0 ? (
            <div className="flex h-48 items-center justify-center text-sm font-bold text-muted-foreground">
              Nothing blocked yet.
            </div>
          ) : (
            <div className="flex h-48 items-end gap-1">
              {series.map((point, i) => (
                <div
                  key={i}
                  className="flex-1 bg-primary"
                  style={{
                    height: `${Math.max(2, (point.value / Math.max(1, ...series.map((s) => s.value))) * 100)}%`,
                    minWidth: '4px',
                  }}
                  title={`${point.label}: ${point.value} blocked`}
                />
              ))}
            </div>
          )}
        </ChartContainer>

        <ChartContainer
          title="Active detection modules"
          subtitle={`${activeInspectors.length} inspectors running`}
        >
          <div className="space-y-2">
            {activeInspectors
              .slice()
              .sort((a, b) => b.hits - a.hits)
              .slice(0, 8)
              .map((ins) => (
                <div key={ins.name} className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold text-foreground font-mono">{ins.name}</span>
                  <Badge
                    variant="outline"
                    className={`border-2 font-black tabular-nums ${
                      ins.hits > 0
                        ? 'border-primary text-primary'
                        : 'border-foreground/30 text-muted-foreground'
                    }`}
                  >
                    {ins.hits}
                  </Badge>
                </div>
              ))}
          </div>
        </ChartContainer>
      </div>

      {entries.length === 0 ? (
        <EmptyState />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Card className="border-2 border-foreground shadow-brutal lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-sm font-black uppercase tracking-tight">
                Recent attacks
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto scrollbar-thin">
                <Table>
                  <TableHeader>
                    <TableRow className="border-foreground">
                      <TableHead className="font-black uppercase text-xs">Time</TableHead>
                      <TableHead className="font-black uppercase text-xs">Rule</TableHead>
                      <TableHead className="font-black uppercase text-xs">Path</TableHead>
                      <TableHead className="font-black uppercase text-xs">Source</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {recent.map((ent) => {
                      const ruleID = ent.metadata.split(':')[0].trim()
                      return (
                        <TableRow key={ent.id} className="border-foreground/30">
                          <TableCell className="text-xs font-mono text-muted-foreground whitespace-nowrap">
                            {formatDate(ent.timestamp)}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={`border-2 font-black text-xs ${severityBadge(ruleID)}`}
                            >
                              {ruleID || ent.action}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs font-mono text-foreground max-w-[200px] truncate">
                            {ent.resource}
                          </TableCell>
                          <TableCell className="text-xs font-mono text-muted-foreground whitespace-nowrap">
                            {ent.actor_ip || '-'}
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>

          <ChartContainer
            title="Top attacker IPs"
            subtitle="Sources of blocked requests"
          >
            <div className="space-y-3">
              {attackers.map((a) => (
                <div key={a.ip}>
                  <div className="flex items-center justify-between text-xs font-bold mb-1">
                    <span className="font-mono text-foreground">{a.ip}</span>
                    <span className="text-muted-foreground tabular-nums">{a.attacks}</span>
                  </div>
                  <div className="h-3 border-2 border-foreground/20 bg-muted">
                    <div
                      className="h-full bg-destructive"
                      style={{ width: `${(a.attacks / attackers[0].attacks) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </ChartContainer>
        </div>
      )}

      {families.length > 0 && (
        <ChartContainer
          title="Rule families triggered"
          subtitle="Which detection signatures are doing the work"
        >
          <div className="flex flex-wrap gap-3">
            {families.map((f) => (
              <div
                key={f.name}
                className="border-2 border-foreground bg-card px-4 py-3 shadow-brutal-sm"
              >
                <div className="text-xs font-black uppercase text-muted-foreground font-mono">
                  {f.name}
                </div>
                <div className="text-2xl font-black text-foreground tabular-nums">{f.value}</div>
                <div className="mt-1.5 h-2 w-20 bg-muted border border-foreground/20">
                  <div
                    className="h-full bg-primary"
                    style={{ width: `${(f.value / maxFamily) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </ChartContainer>
      )}
    </div>
  )
}

function severityBadge(ruleID: string): string {
  const sev = severityFor(ruleID)
  switch (sev) {
    case 'critical':
      return 'border-destructive text-destructive'
    case 'medium':
      return 'border-yellow-500 text-yellow-500'
    default:
      return 'border-orange-500 text-orange-500'
  }
}
