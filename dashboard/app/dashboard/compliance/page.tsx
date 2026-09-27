'use client'

import * as React from 'react'
import { ShieldCheck, ShieldAlert } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { api, ApiError } from '@/lib/api'
import type { ComplianceFramework, ComplianceAssessment } from '@/types'

export default function CompliancePage() {
  const [frameworks, setFrameworks] = React.useState<ComplianceFramework[]>([])
  const [selected, setSelected] = React.useState<ComplianceAssessment | null>(null)
  const [activeID, setActiveID] = React.useState<string>('')
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  const load = React.useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const list = await api.compliance.frameworks()
      setFrameworks(list?.frameworks ?? [])
      if (list.frameworks.length && !activeID) {
        setActiveID(list?.frameworks?.[0]?.id ?? null)
      }
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `${err.message} (HTTP ${err.status})`
          : err instanceof Error ? err.message : 'Unknown error',
      )
    } finally {
      setLoading(false)
    }
  }, [activeID])

  React.useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  React.useEffect(() => {
    if (!activeID) return
    let cancelled = false
    api.compliance
      .assessment(activeID)
      .then((a) => { if (!cancelled) setSelected(a) })
      .catch((err) => {
        if (cancelled) return
        setSelected(null)
        setError(
          err instanceof ApiError
            ? `${err.message} (HTTP ${err.status})`
            : err instanceof Error ? err.message : 'Unknown error',
        )
      })
    return () => { cancelled = true }
  }, [activeID])

  if (error && frameworks.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-black uppercase tracking-tight text-foreground">Compliance</h1>
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
      <div>
        <h1 className="text-2xl font-black uppercase tracking-tight text-foreground">Compliance</h1>
        <p className="text-sm text-muted-foreground font-bold max-w-2xl">
          Control verification against live runtime state. Automated controls are checked
          here; the rest need evidence outside the software and are labelled manual.
        </p>
      </div>

      {loading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-40 border-2 border-foreground/20" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {frameworks.map((fw) => (
            <button
              key={fw.id}
              onClick={() => setActiveID(fw.id)}
              className={`text-left border-2 p-5 shadow-brutal transition-all ${
                activeID === fw.id
                  ? 'border-foreground bg-primary/10 shadow-brutal-primary'
                  : 'border-foreground bg-card hover:shadow-brutal-primary'
              }`}
            >
              <h3 className="font-black uppercase text-foreground tracking-tight">{fw.id}</h3>
              <p className="text-xs text-muted-foreground font-medium mt-1 mb-4">{fw.description}</p>
              <div className="flex items-baseline gap-2">
                <span className="text-4xl font-black text-foreground tabular-nums">
                  {fw.compliant_percent.toFixed(0)}%
                </span>
                <span className="text-xs font-bold text-muted-foreground uppercase">of automated</span>
              </div>
              <div className="mt-3 h-3 border-2 border-foreground/20 bg-muted">
                <div
                  className="h-full bg-primary"
                  style={{ width: `${fw.compliant_percent}%` }}
                />
              </div>
              <p className="text-xs text-muted-foreground font-bold mt-2">
                {fw.compliant}/{fw.automated} automated controls verified · {fw.manual} manual
              </p>
            </button>
          ))}
        </div>
      )}

      {selected ? (
        <Card className="border-2 border-foreground shadow-brutal">
          <CardHeader>
            <CardTitle className="text-sm font-black uppercase tracking-tight">
              {selected.framework} assessment
            </CardTitle>
            <p className="text-xs text-muted-foreground font-medium">
              Assessed {new Date(selected.assessed_at).toLocaleString()}
            </p>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto scrollbar-thin">
              <Table>
                <TableHeader>
                  <TableRow className="border-foreground">
                    <TableHead className="font-black uppercase text-xs">Control</TableHead>
                    <TableHead className="font-black uppercase text-xs">Status</TableHead>
                    <TableHead className="font-black uppercase text-xs">Evidence</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {selected.controls.map((c) => (
                    <TableRow key={c.id} className="border-foreground/30 align-top">
                      <TableCell>
                        <div className="font-mono text-xs font-bold text-foreground">{c.id}</div>
                        <div className="text-xs text-muted-foreground font-medium">{c.name}</div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`border-2 font-black text-xs ${
                            c.status === 'compliant'
                              ? 'border-primary text-primary'
                              : c.status === 'non-compliant'
                                ? 'border-destructive text-destructive'
                                : 'border-foreground/40 text-muted-foreground'
                          }`}
                        >
                          {c.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-md">
                        {c.evidence && c.evidence.length > 0 ? (
                          <ul className="space-y-1">
                            {c.evidence.map((ev, i) => (
                              <li key={i} className="text-xs text-foreground font-medium flex gap-1.5">
                                <ShieldCheck className="w-3.5 h-3.5 mt-0.5 shrink-0 text-primary" />
                                <span>{ev.description}</span>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <span className="text-xs text-muted-foreground italic">
                            {c.remediation || 'No automated evidence — assessed manually.'}
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      ) : (
        !loading && frameworks.length === 0 && (
          <Card className="border-2 border-dashed border-foreground/40">
            <CardContent className="flex flex-col items-center justify-center gap-2 py-12 text-center">
              <ShieldAlert className="w-8 h-8 text-muted-foreground" />
              <p className="text-sm font-bold text-muted-foreground">
                No compliance frameworks available.
              </p>
            </CardContent>
          </Card>
        )
      )}
    </div>
  )
}
