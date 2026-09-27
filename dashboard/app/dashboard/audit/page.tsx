'use client'

import * as React from 'react'
import { ShieldAlert, Fingerprint } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { api, ApiError } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import type { AuditEntry } from '@/types'

export default function AuditPage() {
  const [entries, setEntries] = React.useState<AuditEntry[]>([])
  const [total, setTotal] = React.useState(0)
  const [integrity, setIntegrity] = React.useState<boolean | null>(null)
  const [filter, setFilter] = React.useState('')
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  const load = React.useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const audit = await api.audit()
      setEntries(audit?.entries ?? [])
      setTotal(audit?.total ?? 0)
      setIntegrity(audit?.integrity?.valid ?? null)
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `${err.message} (HTTP ${err.status})`
          : err instanceof Error ? err.message : 'Unknown error',
      )
    } finally {
      setLoading(false)
    }
  }, [])

  React.useEffect(() => {
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [load])

  const filtered = React.useMemo(() => {
    const q = filter.trim().toLowerCase()
    const sorted = [...entries].sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    )
    if (!q) return sorted
    return sorted.filter(
      (e) =>
        e.metadata.toLowerCase().includes(q) ||
        e.actor_ip.toLowerCase().includes(q) ||
        e.resource.toLowerCase().includes(q) ||
        e.action.toLowerCase().includes(q),
    )
  }, [entries, filter])

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-black uppercase tracking-tight text-foreground">Audit log</h1>
        <Card className="border-2 border-destructive shadow-brutal-sm">
          <CardContent className="flex flex-col items-center justify-center gap-3 py-12 text-center">
            <ShieldAlert className="w-10 h-10 text-destructive" />
            <p className="text-sm text-muted-foreground font-medium">{error}</p>
            <Button variant="outline" onClick={load}>Try again</Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-black uppercase tracking-tight text-foreground">Audit log</h1>
          <p className="text-sm text-muted-foreground font-bold">
            {total} {total === 1 ? 'entry' : 'entries'} · hash-chained
          </p>
        </div>
        <Badge
          variant="outline"
          className={`border-2 font-black uppercase ${integrity === null ? 'border-foreground/30 text-muted-foreground' : integrity ? 'border-primary text-primary' : 'border-destructive text-destructive'}`}
        >
          <Fingerprint className="w-3.5 h-3.5 mr-1.5" />
          {integrity === null ? 'unverified' : integrity ? 'chain intact' : 'chain broken'}
        </Badge>
      </div>

      <Input
        placeholder="Filter by rule, IP, path or action..."
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        className="max-w-sm border-2 border-foreground"
      />

      {loading && entries.length === 0 ? (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-12 border-2 border-foreground/20" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <Card className="border-2 border-dashed border-foreground/40">
          <CardContent className="flex flex-col items-center justify-center gap-2 py-12 text-center">
            <ShieldAlert className="w-8 h-8 text-muted-foreground" />
            <p className="text-sm font-bold text-muted-foreground">
              {entries.length === 0
                ? 'No audit entries yet. Blocked requests are recorded here.'
                : 'No entries match this filter.'}
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card className="border-2 border-foreground shadow-brutal">
          <CardHeader>
            <CardTitle className="text-sm font-black uppercase tracking-tight">
              {filtered.length} shown
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto scrollbar-thin">
              <Table>
                <TableHeader>
                  <TableRow className="border-foreground">
                    <TableHead className="font-black uppercase text-xs">Time</TableHead>
                    <TableHead className="font-black uppercase text-xs">Result</TableHead>
                    <TableHead className="font-black uppercase text-xs">Rule</TableHead>
                    <TableHead className="font-black uppercase text-xs">Path</TableHead>
                    <TableHead className="font-black uppercase text-xs">IP</TableHead>
                    <TableHead className="font-black uppercase text-xs">Chain</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.slice(0, 50).map((ent) => (
                    <TableRow key={ent.id} className="border-foreground/30">
                      <TableCell className="text-xs font-mono text-muted-foreground whitespace-nowrap">
                        {formatDate(ent.timestamp)}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`border-2 font-black text-xs ${ent.result === 'blocked' ? 'border-destructive text-destructive' : 'border-foreground/40 text-muted-foreground'}`}
                        >
                          {ent.result}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs font-mono text-foreground whitespace-nowrap">
                        {ent.metadata || '-'}
                      </TableCell>
                      <TableCell className="text-xs font-mono text-muted-foreground max-w-[220px] truncate">
                        {ent.resource}
                      </TableCell>
                      <TableCell className="text-xs font-mono text-muted-foreground whitespace-nowrap">
                        {ent.actor_ip || '-'}
                      </TableCell>
                      <TableCell className="text-xs font-mono text-muted-foreground">
                        {ent.hash.slice(0, 8)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {filtered.length > 50 && (
              <p className="text-xs text-muted-foreground font-bold mt-3">
                Showing the 50 most recent of {filtered.length} matches.
              </p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
