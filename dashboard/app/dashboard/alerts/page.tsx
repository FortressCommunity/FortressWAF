'use client'

import * as React from 'react'
import { Bell, BellOff, Check, Trash2, ShieldAlert } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  AlertDialog,
} from '@/components/ui/alert-dialog'
import { SeverityDot, type Severity } from '@/components/severity'
import { api } from '@/lib/api'
import { usePolling } from '@/lib/use-polling'
import { formatDate } from '@/lib/utils'
import type { AlertsResponse, AlertSeverity, Alert } from '@/types'

const SEVERITIES: AlertSeverity[] = ['critical', 'high', 'medium', 'low']

const SEV_LABEL: Record<AlertSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

function asSeverity(s: string): Severity {
  return (['critical', 'high', 'medium', 'low'] as string[]).includes(s) ? (s as Severity) : 'medium'
}

export default function AlertsPage() {
  const { data, loading, error, reload } = usePolling<AlertsResponse>(() => api.alerts.list(), 3_000)
  const [filter, setFilter] = React.useState<'all' | 'unacked' | AlertSeverity>('unacked')
  const [busy, setBusy] = React.useState<string | null>(null)
  // The alert queued for the confirmation dialog, or null when none is open.
  const [pendingDelete, setPendingDelete] = React.useState<Alert | null>(null)

  const alerts = data?.alerts ?? []
  const shown = alerts.filter((a) => {
    if (filter === 'all') return true
    if (filter === 'unacked') return !a.acknowledged
    return a.severity === filter
  })

  async function ack(id: string) {
    setBusy(id)
    try {
      await api.alerts.ack(id)
      reload()
    } finally {
      setBusy(null)
    }
  }

  async function removeConfirmed(id: string) {
    setPendingDelete(null)
    setBusy(id)
    try {
      await api.alerts.remove(id)
      reload()
    } finally {
      setBusy(null)
    }
  }

  async function ackAll() {
    const unacked = alerts.filter((a) => !a.acknowledged)
    await Promise.all(unacked.map((a) => api.alerts.ack(a.id).catch(() => {})))
    reload()
  }

  const bySeverity = data?.by_severity ?? {}

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Alerts</h1>
          <p className="text-sm text-muted-foreground">Security events that need triage</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs tabular-nums text-muted-foreground">
            {data?.unacked ?? 0} open / {data?.total ?? 0} total
          </span>
          <Button variant="outline" size="sm" onClick={ackAll} disabled={(data?.unacked ?? 0) === 0}>
            <Check className="w-3.5 h-3.5" /> Acknowledge all
          </Button>
        </div>
      </div>

      {/* Severity counters + filter in one strip. */}
      <div className="glass flex flex-wrap items-center gap-2 rounded-panel p-2">
        <button
          type="button"
          onClick={() => setFilter('unacked')}
          aria-pressed={filter === 'unacked'}
          className={`rounded-control px-3 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 ${
            filter === 'unacked' ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          Open ({data?.unacked ?? 0})
        </button>
        <button
          type="button"
          onClick={() => setFilter('all')}
          aria-pressed={filter === 'all'}
          className={`rounded-control px-3 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 ${
            filter === 'all' ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          All ({data?.total ?? 0})
        </button>
        <div className="mx-1 h-5 w-px bg-border" />
        {SEVERITIES.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setFilter(s)}
            aria-pressed={filter === s}
            className={`inline-flex items-center gap-1.5 rounded-control px-2.5 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 ${
              filter === s ? 'bg-muted text-foreground' : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <SeverityDot severity={asSeverity(s)} />
            {SEV_LABEL[s]}
            <span className="font-mono tabular-nums text-muted-foreground">{bySeverity[s] ?? 0}</span>
          </button>
        ))}
      </div>

      {error ? (
        <Card className="border border-destructive/40">
          <CardContent className="flex flex-col items-center gap-3 py-10 text-center">
            <ShieldAlert className="h-9 w-9 text-destructive" />
            <div>
              <h2 className="font-semibold text-foreground">Could not load alerts</h2>
              <p className="mt-1 max-w-md text-sm text-muted-foreground">{error}</p>
            </div>
            <Button variant="outline" onClick={() => reload()}>Try again</Button>
          </CardContent>
        </Card>
      ) : loading && alerts.length === 0 ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}
        </div>
      ) : shown.length === 0 ? (
        <Card className="border border-dashed">
          <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
            <BellOff className="h-9 w-9 text-primary" />
            <div>
              <h2 className="font-semibold text-foreground">
                {filter === 'unacked' ? 'No open alerts' : 'Nothing here'}
              </h2>
              <p className="mt-1 max-w-md text-sm text-muted-foreground">
                Alerts appear when the WAF blocks a high or critical attack. Send a payload
                through the proxy to raise one.
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <ul className="space-y-2">
          {shown.map((a) => (
            <li
              key={a.id}
              className={`glass flex items-start gap-3 rounded-panel p-3 ${
                a.acknowledged ? 'opacity-60' : ''
              }`}
            >
              <div className="pt-1.5">
                <SeverityDot severity={asSeverity(a.severity)} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-foreground">{a.title}</span>
                  <span className="rounded-control border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                    {a.source}
                  </span>
                  {a.acknowledged && (
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-muted-foreground">
                      <Check className="h-3 w-3" /> acked
                    </span>
                  )}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{a.detail}</p>
                <p className="mt-1 font-mono text-[11px] tabular-nums text-muted-foreground/70">
                  {a.id} · {formatDate(a.created_at)}
                  {a.acked_by ? ` · by ${a.acked_by}` : ''}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-1">
                {!a.acknowledged && (
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={busy === a.id}
                    onClick={() => ack(a.id)}
                    aria-label={`Acknowledge ${a.title}`}
                  >
                    <Check className="w-3.5 h-3.5" /> Ack
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  disabled={busy === a.id}
                  onClick={() => setPendingDelete(a)}
                  aria-label={`Delete ${a.title}`}
                >
                  <Trash2 className="h-4 w-4 text-muted-foreground" />
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}

      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <Bell className="h-3 w-3" />
        Alerts are raised automatically when the WAF blocks a high or critical attack.
      </p>

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => { if (!open) setPendingDelete(null) }}
        title="Delete this alert?"
        description={
          pendingDelete
            ? `“${pendingDelete.title}” (${pendingDelete.id}) will be removed from the inbox. This cannot be undone.`
            : ''
        }
        confirmLabel={`Delete ${pendingDelete?.source ?? 'alert'}`}
        busy={busy === pendingDelete?.id}
        onConfirm={() => pendingDelete && removeConfirmed(pendingDelete.id)}
      />
    </div>
  )
}
