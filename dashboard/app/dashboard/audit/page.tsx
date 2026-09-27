'use client'

import * as React from 'react'
import { ShieldAlert, Fingerprint } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { api } from '@/lib/api'
import { usePolling } from '@/lib/use-polling'
import { formatDate } from '@/lib/utils'
import type { AuditEntry, AuditResponse } from '@/types'

export default function AuditPage() {
  const { data, loading, error, reload } = usePolling<AuditResponse>(() => api.audit(), 5_000)
  const [filter, setFilter] = React.useState('')

  // Memoized so the derived array keeps its identity between polls and the
  // filter below does not recompute on every render.
  const entries = React.useMemo(() => data?.entries ?? [], [data])
  const total = data?.total ?? 0
  const integrity = data?.integrity?.valid ?? null

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
        <h1 className="text-2xl font-semibold text-foreground">Audit log</h1>
        <Card className="border border-destructive/40">
          <CardContent className="flex flex-col items-center justify-center gap-3 py-12 text-center">
            <ShieldAlert className="w-10 h-10 text-destructive" />
            <p className="text-sm text-muted-foreground">{error}</p>
            <Button variant="outline" onClick={() => reload()}>Try again</Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Audit log</h1>
          <p className="text-sm text-muted-foreground">
            {total} {total === 1 ? 'entry' : 'entries'} · hash-chained
          </p>
        </div>
        <Badge
          variant="outline"
        className={`font-medium ${integrity === null ? 'text-muted-foreground' : integrity ? 'border-primary text-primary' : 'border-destructive text-destructive'}`}
        >
          <Fingerprint className="w-3.5 h-3.5 mr-1.5" />
          {integrity === null ? 'unverified' : integrity ? 'chain intact' : 'chain broken'}
        </Badge>
      </div>

      <Input
        placeholder="Filter by rule, IP, path or action..."
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        className="max-w-sm"
      />

      {loading && entries.length === 0 ? (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-12" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <Card className="border border-dashed">
          <CardContent className="flex flex-col items-center justify-center gap-2 py-12 text-center">
            <ShieldAlert className="w-8 h-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              {entries.length === 0
                ? 'No audit entries yet. Blocked requests are recorded here.'
                : 'No entries match this filter.'}
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold">
              {filtered.length} shown
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto scrollbar-thin">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead>Rule</TableHead>
                    <TableHead>Path</TableHead>
                    <TableHead>IP</TableHead>
                    <TableHead>Chain</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.slice(0, 50).map((ent) => (
                    <TableRow key={ent.id}>
                      <TableCell className="text-xs font-mono text-muted-foreground whitespace-nowrap">
                        {formatDate(ent.timestamp)}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`font-medium text-xs ${ent.result === 'blocked' ? 'border-destructive text-destructive' : 'text-muted-foreground'}`}
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
              <p className="text-xs text-muted-foreground mt-3">
                Showing the 50 most recent of {filtered.length} matches.
              </p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
