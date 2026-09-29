'use client'

import * as React from 'react'
import { BarChart3, ShieldAlert } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ChartContainer } from '@/components/ui/chart'
import { SeverityTag } from '@/components/severity'
import { api } from '@/lib/api'
import { usePolling } from '@/lib/use-polling'
import { formatNumber } from '@/lib/utils'
import type { AnalyticsResponse } from '@/types'

// Horizontal bar list used for the three category breakdowns.
function BarList({
  items,
  renderLabel,
  barClass = 'bg-primary/70',
  emptyHint,
}: {
  items: Array<{ key: string; count: number; node?: React.ReactNode }>
  renderLabel?: (key: string) => React.ReactNode
  barClass?: string
  emptyHint: string
}) {
  const max = Math.max(1, ...items.map((i) => i.count))
  if (items.length === 0) {
    return <p className="py-6 text-center text-sm text-muted-foreground">{emptyHint}</p>
  }
  return (
    <div className="space-y-3">
      {items.map((i) => (
        <div key={i.key}>
          <div className="mb-1 flex items-center justify-between gap-2 text-xs">
            <span className="min-w-0 truncate font-mono text-foreground">
              {renderLabel ? renderLabel(i.key) : i.key}
            </span>
            <span className="shrink-0 font-mono tabular-nums text-muted-foreground">{i.count}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-muted">
            <div className={`h-full rounded-full ${barClass}`} style={{ width: `${(i.count / max) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  )
}

export default function AnalyticsPage() {
  const { data, loading, error, reload } = usePolling<AnalyticsResponse>(() => api.analytics(), 5_000)
  // Window selector: the API returns 30 one-minute buckets; showing the last
  // 15 or 30 lets the operator zoom the timeline without another request.
  const [windowMin, setWindowMin] = React.useState<15 | 30>(30)

  if (error) {
    return (
      <div className="space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Analytics</h1>
          <p className="text-sm text-muted-foreground">Threat distribution from the audit log</p>
        </div>
        <Card className="border border-destructive/40">
          <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
            <ShieldAlert className="h-10 w-10 text-destructive" />
            <p className="max-w-md text-sm text-muted-foreground">{error}</p>
            <Button variant="outline" onClick={() => reload()}>Try again</Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  const series = data?.series ?? []
  const visible = windowMin === 15 ? series.slice(-15) : series
  const attackers = (data?.top_attackers ?? []).map((a) => ({ key: a.ip, count: a.count }))
  const rules = (data?.top_rules ?? []).map((r) => ({ key: r.rule, count: r.count }))
  const actions = (data?.by_action ?? []).map((a) => ({ key: a.action, count: a.count }))
  const results = (data?.by_result ?? []).map((r) => ({ key: r.result, count: r.count }))
  const peak = Math.max(1, ...visible.map((s) => s.count))
  const total = data?.total_events ?? 0

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Analytics</h1>
          <p className="text-sm text-muted-foreground">Threat distribution from the audit log</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <BarChart3 className="h-3.5 w-3.5" />
          {formatNumber(total)} events analysed
        </div>
      </div>

      <ChartContainer
        title="Events per minute"
        subtitle={`Blocked requests over the last ${windowMin} minutes`}
      >
        <div className="mb-3 flex items-center gap-1 rounded-control border border-border p-0.5">
          {([15, 30] as const).map((w) => (
            <button
              key={w}
              type="button"
              onClick={() => setWindowMin(w)}
              aria-pressed={windowMin === w}
              className={`rounded-control px-2.5 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 ${
                windowMin === w ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {w}m
            </button>
          ))}
        </div>
        {loading && series.length === 0 ? (
          <Skeleton className="h-40 w-full" />
        ) : (
          <div className="flex h-40 items-end gap-[3px]">
            {visible.map((p, i) => (
              <div
                key={i}
                className="flex-1 rounded-t-[2px] bg-primary/70"
                style={{ height: `${Math.max(2, (p.count / peak) * 100)}%`, minWidth: '3px' }}
                title={`${p.minute}: ${p.count} events`}
              />
            ))}
          </div>
        )}
        <div className="mt-2 flex justify-between font-mono text-[10px] tabular-nums text-muted-foreground">
          <span>{visible[0]?.minute ?? ''}</span>
          <span>peak {peak}/min</span>
          <span>{visible[visible.length - 1]?.minute ?? ''}</span>
        </div>
      </ChartContainer>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ChartContainer title="Top attacker IPs" subtitle="Blocked-request sources">
          <BarList
            items={attackers}
            barClass="bg-destructive/70"
            emptyHint="No attacks recorded yet."
          />
        </ChartContainer>

        <ChartContainer title="Top rules triggered" subtitle="Which signatures fired">
          <BarList
            items={rules}
            barClass="bg-warning/70"
            emptyHint="No rules have fired yet."
            renderLabel={(k) => <SeverityTag ruleID={k} />}
          />
        </ChartContainer>

        <div className="space-y-4">
          <ChartContainer title="By action" subtitle="Engine decision">
            <BarList
              items={actions}
              emptyHint="No decisions logged."
            />
          </ChartContainer>
          <ChartContainer title="By result" subtitle="Outcome">
            <BarList
              items={results}
              barClass="bg-muted-foreground/50"
              emptyHint="No results logged."
            />
          </ChartContainer>
        </div>
      </div>
    </div>
  )
}
