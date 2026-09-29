'use client'

import * as React from 'react'
import { Radio, Search, ShieldAlert, ShieldCheck, Download, X, Ban, ChevronRight } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { useToast } from '@/components/ui/toast'
import { MetaItem, SeverityTag } from '@/components/severity'
import { api, ApiError } from '@/lib/api'
import { usePolling } from '@/lib/use-polling'
import { formatDate } from '@/lib/utils'
import type { TrafficResponse, AuditEntry } from '@/types'

const ACTIONS = [
  { value: '', label: 'All events' },
  { value: 'request_blocked', label: 'Blocked' },
  { value: 'request_allowed', label: 'Allowed' },
  { value: 'request_monitored', label: 'Monitored' },
]

// ruleFromMetadata pulls the rule id out of "SQLI016: SQL Pattern Match".
// metadata can be absent (an entry logged without a rule), so it is guarded --
// the previous version crashed the whole page on the first null metadata.
function ruleFromMetadata(meta?: string): string {
  if (!meta) return ''
  return meta.split(':')[0].trim()
}

function deviceTag(device?: string): string {
  switch (device) {
    case 'mobile': return 'text-primary'
    case 'bot': return 'text-destructive'
    case 'tool': return 'text-warning'
    case 'tablet': return 'text-primary'
    default: return 'text-muted-foreground'
  }
}

// HeaderDetail shows the full header set of one request, so an operator can
// see exactly what a client sent without leaving the page.
function HeaderDetail({ entry }: { entry: AuditEntry }) {
  const headers = entry.headers ?? {}
  const keys = Object.keys(headers)
  return (
    <div className="space-y-3 bg-muted/20 px-4 py-3">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <MetaItem label="Source IP" value={entry.actor_ip || '—'} mono />
        <MetaItem label="Browser" value={entry.browser || 'unknown'} />
        <MetaItem label="Device" value={entry.device || '—'} />
      </div>
      <div>
        <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
          User-Agent
        </p>
        <p className="break-all font-mono text-[11px] text-muted-foreground">{entry.user_agent || '—'}</p>
      </div>
      <div>
        <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
          Headers ({keys.length})
        </p>
        <div className="max-h-56 overflow-y-auto rounded-control border border-border/60 bg-background/40 scrollbar-thin">
          <table className="w-full text-left font-mono text-[11px]">
            <tbody>
              {keys.sort().map((k) => (
                <tr key={k} className="border-b border-border/40 last:border-0">
                  <td className="w-1/3 py-1 pl-2 pr-2 align-top text-muted-foreground/80">{k}</td>
                  <td className="break-all py-1 pr-2 text-foreground">{headers[k]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default function TrafficPage() {
  const { toast } = useToast()
  const [query, setQuery] = React.useState('')
  const [action, setAction] = React.useState('')
  const [debouncedQuery, setDebouncedQuery] = React.useState('')
  const [expanded, setExpanded] = React.useState<string | null>(null)
  const [banning, setBanning] = React.useState<string | null>(null)

  // Debounce the search box so typing does not fire a request per keystroke.
  React.useEffect(() => {
    const id = setTimeout(() => setDebouncedQuery(query.trim()), 250)
    return () => clearTimeout(id)
  }, [query])

  const { data, loading, error, reload } = usePolling<TrafficResponse>(
    () => api.traffic({ q: debouncedQuery || undefined, action: action || undefined, limit: 300 }),
    2_000,
  )

  const entries = data?.entries ?? []
  const blocked = entries.filter((e) => e.result === 'blocked').length
  const allowed = entries.length - blocked

  async function banIP(ip: string) {
    if (!ip) return
    setBanning(ip)
    try {
      await api.bans.add({ ip, reason: 'Banned from live traffic view', ttl_seconds: 86400 })
      toast({ title: 'IP banned', description: `${ip} is blocked for 24 hours.`, variant: 'success' })
    } catch (err) {
      toast({ title: 'Ban failed', description: err instanceof ApiError ? err.message : 'Try again.' })
    } finally {
      setBanning(null)
    }
  }

  function exportCSV() {
    const header = 'timestamp,method,rule,path,ip,browser,device,user_agent,result\n'
    const rows = entries
      .map((e) =>
        [
          e.timestamp,
          e.method || '',
          ruleFromMetadata(e.metadata),
          `"${(e.path || e.resource).replace(/"/g, '""')}"`,
          e.actor_ip || '',
          `"${(e.browser || '').replace(/"/g, '""')}"`,
          e.device || '',
          `"${(e.user_agent || '').replace(/"/g, '""')}"`,
          e.result,
        ].join(','),
      )
      .join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `fortresswaf-traffic-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Live traffic</h1>
          <p className="text-sm text-muted-foreground">Every inspected request, newest first</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="gap-1.5 font-medium">
            <Radio className="w-3 h-3 text-primary" />
            {loading ? 'syncing' : 'live'}
          </Badge>
          <Button variant="outline" size="sm" onClick={exportCSV} disabled={entries.length === 0}>
            <Download className="w-3.5 h-3.5" /> Export CSV
          </Button>
        </div>
      </div>

      {/* Toolbar: filters + counters on one dense row. */}
      <div className="glass flex flex-wrap items-center gap-2 rounded-panel p-2">
        <div className="relative min-w-[200px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by path, IP, or rule…"
            aria-label="Filter traffic"
            className="h-9 pl-8"
          />
          {query && (
            <button
              type="button"
              aria-label="Clear filter"
              onClick={() => setQuery('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <div className="flex w-full items-center gap-1 overflow-x-auto rounded-control border border-border p-0.5 scrollbar-thin sm:w-auto">
          {ACTIONS.map((a) => (
            <button
              key={a.value}
              type="button"
              onClick={() => setAction(a.value)}
              aria-pressed={action === a.value}
              className={`shrink-0 rounded-control px-2.5 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 ${
                action === a.value
                  ? 'bg-primary/15 text-primary'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {a.label}
            </button>
          ))}
        </div>

        <div className="flex w-full items-center gap-4 sm:w-auto sm:border-l sm:border-border sm:pl-3 sm:pr-1">
          <MetaItem label="Shown" value={entries.length} mono />
          <MetaItem label="Blocked" value={blocked} mono />
          <MetaItem label="Allowed" value={allowed} mono />
        </div>
      </div>

      {error ? (
        <Card className="border border-destructive/40">
          <CardContent className="flex flex-col items-center gap-3 py-10 text-center">
            <ShieldAlert className="h-9 w-9 text-destructive" />
            <div>
              <h2 className="font-semibold text-foreground">Could not load traffic</h2>
              <p className="mt-1 max-w-md text-sm text-muted-foreground">{error}</p>
            </div>
            <Button variant="outline" onClick={() => reload()}>Try again</Button>
          </CardContent>
        </Card>
      ) : loading && entries.length === 0 ? (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-11 w-full" />
          ))}
        </div>
      ) : entries.length === 0 ? (
        <Card className="border border-dashed">
          <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
            <ShieldCheck className="h-9 w-9 text-primary" />
            <div>
              <h2 className="font-semibold text-foreground">
                {debouncedQuery || action ? 'No events match this filter' : 'No traffic yet'}
              </h2>
              <p className="mt-1 max-w-md text-sm text-muted-foreground">
                {debouncedQuery || action
                  ? 'Try a different search term or clear the filter.'
                  : 'Send a request through the proxy and it will appear here within a second.'}
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Mobile: a stacked card per event. A nine-column table is not
              usable on a phone, so below md each row becomes a card showing
              time, rule, path, client, result, with the header detail on tap. */}
          <ul className="space-y-2 md:hidden">
            {entries.map((e) => {
              const rule = ruleFromMetadata(e.metadata)
              const open = expanded === e.id
              return (
                <li key={e.id} className="glass overflow-hidden rounded-panel">
                  <button
                    type="button"
                    onClick={() => setExpanded(open ? null : e.id)}
                    aria-expanded={open}
                    className="w-full p-3 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <SeverityTag ruleID={rule || e.action} />
                      <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
                        {formatDate(e.timestamp)}
                      </span>
                    </div>
                    <p className="mt-2 truncate font-mono text-xs text-foreground">
                      <span className="text-muted-foreground">{e.method || 'GET'} </span>
                      {e.path || e.resource}
                    </p>
                    <div className="mt-2 flex items-center justify-between gap-2 text-[11px]">
                      <span className="font-mono text-muted-foreground">{e.actor_ip || '—'}</span>
                      <span className="flex items-center gap-2">
                        <span className={`font-medium ${deviceTag(e.device)}`}>{e.device || '—'}</span>
                        <span className={e.result === 'blocked' ? 'font-medium text-destructive' : 'text-muted-foreground'}>
                          {e.result}
                        </span>
                      </span>
                    </div>
                  </button>
                  {open && (
                    <div className="border-t border-border/60">
                      <HeaderDetail entry={e} />
                      <div className="flex justify-end px-3 pb-3">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={banning === e.actor_ip || !e.actor_ip}
                          onClick={() => banIP(e.actor_ip)}
                        >
                          <Ban className="h-3.5 w-3.5" /> Ban {e.actor_ip || 'source'}
                        </Button>
                      </div>
                    </div>
                  )}
                </li>
              )
            })}
          </ul>

          {/* Desktop / tablet: the full table. */}
          <Card className="hidden overflow-hidden md:block">
            <div className="max-h-[calc(100vh-16rem)] overflow-auto scrollbar-thin">
              <table className="w-full border-collapse text-left">
                <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                  <tr className="border-b border-border text-[11px] uppercase tracking-wider text-muted-foreground">
                    <th className="w-8 px-2 py-2" />
                    <th className="px-3 py-2 font-medium">Time</th>
                    <th className="px-3 py-2 font-medium">Rule</th>
                    <th className="px-3 py-2 font-medium">Method</th>
                    <th className="px-3 py-2 font-medium">Path</th>
                    <th className="px-3 py-2 font-medium">Source IP</th>
                    <th className="px-3 py-2 font-medium">Client</th>
                    <th className="px-3 py-2 font-medium">Result</th>
                    <th className="px-3 py-2 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => {
                    const rule = ruleFromMetadata(e.metadata)
                    const open = expanded === e.id
                    return (
                      <React.Fragment key={e.id}>
                        <tr
                          onClick={() => setExpanded(open ? null : e.id)}
                          className="cursor-pointer border-b border-border/60 text-sm transition-colors duration-100 hover:bg-muted/50"
                        >
                          <td className="px-2 py-2">
                            <ChevronRight className={`h-3.5 w-3.5 text-muted-foreground transition-transform ${open ? 'rotate-90' : ''}`} />
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 font-mono text-xs tabular-nums text-muted-foreground">
                            {formatDate(e.timestamp)}
                          </td>
                          <td className="px-3 py-2">
                            <SeverityTag ruleID={rule || e.action} />
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-muted-foreground">{e.method || '—'}</td>
                          <td className="max-w-[18rem] truncate px-3 py-2 font-mono text-xs text-foreground" title={e.resource}>
                            {e.path || e.resource}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-muted-foreground">{e.actor_ip || '—'}</td>
                          <td className="whitespace-nowrap px-3 py-2 text-xs">
                            <span className={`font-medium ${deviceTag(e.device)}`}>{e.device || '—'}</span>
                            <span className="ml-2 text-muted-foreground">{e.browser || ''}</span>
                          </td>
                          <td className="px-3 py-2 text-xs font-medium">
                            <span className={e.result === 'blocked' ? 'text-destructive' : 'text-muted-foreground'}>{e.result}</span>
                          </td>
                          <td className="px-3 py-2 text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={banning === e.actor_ip || !e.actor_ip}
                              onClick={(ev) => { ev.stopPropagation(); banIP(e.actor_ip) }}
                              aria-label={`Ban ${e.actor_ip}`}
                            >
                              <Ban className="h-3.5 w-3.5" />
                            </Button>
                          </td>
                        </tr>
                        {open && (
                          <tr className="border-b border-border/60">
                            <td colSpan={9} className="p-0">
                              <HeaderDetail entry={e} />
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  )
}
