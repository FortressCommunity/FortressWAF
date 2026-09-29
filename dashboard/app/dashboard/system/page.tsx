'use client'

import * as React from 'react'
import { Activity, RefreshCw, ShieldCheck, Boxes, Cpu, Server, GraduationCap } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { useToast } from '@/components/ui/toast'
import { api, ApiError } from '@/lib/api'
import { usePolling } from '@/lib/use-polling'
import { formatNumber, formatDuration } from '@/lib/utils'
import type { ConfigDetail, MetricsSnapshot, Status, InspectorsResponse, TrainingStatus } from '@/types'

interface SystemData {
  metrics: MetricsSnapshot | null
  config: ConfigDetail | null
  status: Status | null
  inspectors: InspectorsResponse | null
  training: TrainingStatus | null
}

function Metric({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div className="rounded-control border border-border bg-muted/20 px-3 py-2.5">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">{label}</p>
      <p className="mt-1 font-mono text-lg tabular-nums text-foreground">{value}</p>
      {hint && <p className="mt-0.5 text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  )
}

function ModuleRow({ name, on }: { name: string; on: boolean }) {
  return (
    <div className="flex items-center justify-between gap-2 border-b border-border/50 py-1.5 last:border-0">
      <span className="font-mono text-xs text-foreground">{name}</span>
      <Badge
        variant="outline"
        className={`font-medium ${on ? 'border-primary/50 text-primary' : 'text-muted-foreground'}`}
      >
        {on ? 'enabled' : 'off'}
      </Badge>
    </div>
  )
}

export default function SystemPage() {
  const { toast } = useToast()
  const { data, loading, error, reload } = usePolling<SystemData>(
    async () => {
      const [metrics, config, status, inspectors, training] = await Promise.all([
        api.metrics().catch(() => null),
        api.configDetail().catch(() => null),
        api.status().catch(() => null),
        api.inspectors().catch(() => null),
        api.trainingStatus().catch(() => null),
      ])
      return { metrics, config, status, inspectors, training }
    },
    3_000,
  )
  const [reloading, setReloading] = React.useState(false)

  async function reloadConfig() {
    setReloading(true)
    try {
      await api.reloadConfig()
      toast({ title: 'Configuration reloaded', description: 'The WAF applied the current config file.' })
      reload()
    } catch (err) {
      toast({
        title: 'Reload failed',
        description: err instanceof ApiError ? err.message : 'Could not reload configuration.',
      })
    } finally {
      setReloading(false)
    }
  }

  const m = data?.metrics ?? null
  const c = data?.config ?? null
  const modules = c?.modules ?? {}
  const inspectors = (data?.inspectors?.inspectors ?? []).filter((i) => i.enabled)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-foreground">System</h1>
          <p className="text-sm text-muted-foreground">Runtime state, modules, and configuration</p>
        </div>
        <Button variant="outline" size="sm" onClick={reloadConfig} disabled={reloading}>
          <RefreshCw className={`w-3.5 h-3.5 ${reloading ? 'animate-spin' : ''}`} /> Reload config
        </Button>
      </div>

      {error ? (
        <Card className="border border-destructive/40">
          <CardContent className="py-10 text-center text-sm text-muted-foreground">{error}</CardContent>
        </Card>
      ) : loading && !m ? (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-20" />)}
        </div>
      ) : (
        <>
          {/* One dominant figure (block rate) with the supporting counters as a
              secondary row: the eye lands on the posture number first, not on a
              uniform grid of equal cards. */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-1">
              <CardContent className="flex flex-col justify-between p-5">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                    Block rate
                  </p>
                  <p className="mt-2 font-mono text-5xl font-semibold tabular-nums text-foreground">
                    {(m?.block_rate_percent ?? 0).toFixed(1)}
                    <span className="ml-1 text-2xl text-muted-foreground">%</span>
                  </p>
                </div>
                <div className="mt-4 space-y-1 border-t border-border pt-3 text-xs text-muted-foreground">
                  <p className="flex justify-between"><span>Blocked</span><span className="font-mono tabular-nums text-foreground">{formatNumber(m?.requests_blocked ?? 0)}</span></p>
                  <p className="flex justify-between"><span>Total</span><span className="font-mono tabular-nums text-foreground">{formatNumber(m?.requests_total ?? 0)}</span></p>
                </div>
              </CardContent>
            </Card>

            <div className="grid grid-cols-2 gap-3 lg:col-span-2 lg:grid-cols-3">
              <Metric label="Uptime" value={formatDuration(m?.uptime_seconds ?? 0)} hint={`${m?.active_connections ?? 0} active conns`} />
              <Metric label="Throughput" value={`${(m?.requests_per_second ?? 0).toFixed(1)}/s`} hint="since start" />
              <Metric label="Allowed" value={formatNumber(m?.requests_allowed ?? 0)} hint={`${formatNumber(m?.requests_monitored ?? 0)} monitored`} />
              <Metric label="Challenged" value={formatNumber(m?.requests_challenged ?? 0)} />
              <Metric label="Rate limited" value={formatNumber(m?.requests_rate_limited ?? 0)} />
              <Metric label="Excluded" value={formatNumber(m?.requests_excluded ?? 0)} hint="bypass paths" />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Boxes className="h-4 w-4 text-primary" /> Detection modules
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="max-h-72 overflow-y-auto scrollbar-thin pr-1">
                  {Object.keys(modules).length === 0 ? (
                    <p className="text-sm text-muted-foreground">No module data.</p>
                  ) : (
                    Object.entries(modules)
                      .sort(([a], [b]) => a.localeCompare(b))
                      .map(([name, on]) => <ModuleRow key={name} name={name} on={on} />)
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Cpu className="h-4 w-4 text-primary" /> Active inspectors
                </CardTitle>
              </CardHeader>
              <CardContent>
                {inspectors.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No inspectors running.</p>
                ) : (
                  <div className="max-h-72 space-y-1 overflow-y-auto scrollbar-thin pr-1">
                    {inspectors.map((i) => (
                      <div key={i.name} className="flex items-center justify-between gap-2 border-b border-border/50 py-1.5 last:border-0">
                        <span className="font-mono text-xs text-foreground">{i.name}</span>
                        <span className="font-mono text-xs tabular-nums text-muted-foreground">{i.hits} hits</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Server className="h-4 w-4 text-primary" /> Posture
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <PostureRow label="TLS termination" on={c?.tls_enabled ?? false} goodWhenOn />
                <PostureRow label="Response inspection blocking" on={c?.response_inspect_blocks ?? false} goodWhenOn />
                <PostureRow label="Shadow mode (log only)" on={c?.shadow_mode ?? false} />
                <PostureRow label="Learning mode" on={c?.learning_mode ?? false} />
                <PostureRow label="Prometheus metrics" on={c?.prometheus ?? false} goodWhenOn />
                <div className="mt-3 flex items-center gap-2 border-t border-border pt-3 text-xs text-muted-foreground">
                  <Activity className="h-3.5 w-3.5" />
                  {formatNumber(c?.sites_count ?? 0)} sites · {formatNumber(c?.rules_count ?? 0)} rules
                </div>
                <div className="mt-2 flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Build</span>
                  <span className="font-mono text-foreground">
                    {c?.version ?? 'dev'}
                    {c?.commit && c.commit !== 'unknown' ? ` · ${c.commit.slice(0, 8)}` : ''}
                  </span>
                </div>
              </CardContent>
            </Card>
          </div>

          {!c?.response_inspect_blocks && (
            <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <ShieldCheck className="h-3 w-3 text-primary" />
              Response inspection runs in monitor mode: leaks are logged, not blocked.
              Set <code className="font-mono">response_inspect.block: true</code> to enforce.
            </p>
          )}

          {/* Live training corpus status. */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <GraduationCap className="h-4 w-4 text-primary" /> Training corpus
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              {!data?.training?.enabled ? (
                <p className="text-muted-foreground">
                  {data?.training?.note ?? 'Collection is disabled.'}
                </p>
              ) : (
                <>
                  <div className="grid grid-cols-3 gap-3">
                    <Metric label="Collected" value={formatNumber(data.training.collected ?? 0)} />
                    <Metric label="Unique" value={formatNumber(data.training.unique ?? 0)} />
                    <Metric label="Dropped" value={formatNumber(data.training.dropped ?? 0)} hint="failed quality checks" />
                  </div>
                  <div>
                    <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                      Corpus by class
                    </p>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-3">
                      {Object.entries(data.training.corpus_sizes ?? {})
                        .sort(([a], [b]) => a.localeCompare(b))
                        .map(([cat, n]) => (
                          <div key={cat} className="flex items-center justify-between text-xs">
                            <span className="font-mono text-muted-foreground">{cat}</span>
                            <span className="font-mono tabular-nums text-foreground">{n}</span>
                          </div>
                        ))}
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Only high-confidence attack families (score ≥ 70) are collected and labelled by rule.
                    The sidecar retrains from this corpus and keeps the new model only if it scores at least as well.
                  </p>
                </>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}

function PostureRow({ label, on, goodWhenOn }: { label: string; on: boolean; goodWhenOn?: boolean }) {
  const good = goodWhenOn ? on : !on
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className={`font-mono text-xs font-medium ${good ? 'text-primary' : 'text-warning'}`}>
        {on ? 'on' : 'off'}
      </span>
    </div>
  )
}
