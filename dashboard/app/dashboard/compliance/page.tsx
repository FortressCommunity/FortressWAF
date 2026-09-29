'use client'

import * as React from 'react'
import { ShieldCheck, ShieldAlert } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { api, ApiError } from '@/lib/api'
import { usePolling } from '@/lib/use-polling'
import type { ComplianceFramework, ComplianceAssessment } from '@/types'

export default function CompliancePage() {
  const { data, loading, error, reload } = usePolling(
    () => api.compliance.frameworks(),
    60_000,
  )
  const frameworks = React.useMemo(() => data?.frameworks ?? [], [data])

  // User selection, falling back to the first framework once the list loads.
  // Derived rather than set in an effect so the default tracks the data.
  const [activeID, setActiveID] = React.useState<string>('')
  const selectedID = activeID || frameworks[0]?.id || ''

  const [selected, setSelected] = React.useState<ComplianceAssessment | null>(null)
  const [assessmentError, setAssessmentError] = React.useState<string | null>(null)

  React.useEffect(() => {
    if (!selectedID) return
    let cancelled = false
    api.compliance
      .assessment(selectedID)
      .then((a) => {
        if (cancelled) return
        setSelected(a)
        setAssessmentError(null)
      })
      .catch((err) => {
        if (cancelled) return
        setSelected(null)
        setAssessmentError(
          err instanceof ApiError
            ? `${err.message} (HTTP ${err.status})`
            : err instanceof Error ? err.message : 'Unknown error',
        )
      })
    return () => { cancelled = true }
  }, [selectedID])

  if (error && frameworks.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-foreground">Compliance</h1>
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
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Compliance</h1>
        <p className="text-sm text-muted-foreground max-w-2xl">
          Control verification against live runtime state. Automated controls are checked
          here; the rest need evidence outside the software and are labelled manual.
        </p>
      </div>

      <h2 className="sr-only">Frameworks</h2>

      {loading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-40" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {frameworks.map((fw) => (
            <button
              key={fw.id}
              onClick={() => setActiveID(fw.id)}
              className={`glass rounded-panel text-left p-5 transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
                selectedID === fw.id ? 'ring-2 ring-primary' : 'hover:bg-muted/40'
              }`}
            >
              <h3 className="font-semibold text-foreground tracking-tight">{fw.id}</h3>
              <p className="text-xs text-muted-foreground mt-1 mb-4">{fw.description}</p>
              <div className="flex items-baseline gap-2">
                <span className="text-4xl font-semibold text-foreground tabular-nums">
                  {fw.compliant_percent.toFixed(0)}%
                </span>
                <span className="text-xs text-muted-foreground">of automated</span>
              </div>
              <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary"
                  style={{ width: `${fw.compliant_percent}%` }}
                />
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                {fw.compliant}/{fw.automated} automated controls verified · {fw.manual} manual
              </p>
            </button>
          ))}
        </div>
      )}

      {selected ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold">
              {selected.framework} assessment
            </CardTitle>
            <p className="text-xs text-muted-foreground">
              Assessed {new Date(selected.assessed_at).toLocaleString()}
            </p>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto scrollbar-thin">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Control</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Evidence</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {selected.controls.map((c) => (
                    <TableRow key={c.id} className="align-top">
                      <TableCell>
                        <div className="font-mono text-xs font-medium text-foreground">{c.id}</div>
                        <div className="text-xs text-muted-foreground">{c.name}</div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`font-medium text-xs ${
                            c.status === 'compliant'
                              ? 'border-primary text-primary'
                              : c.status === 'non-compliant'
                                ? 'border-destructive text-destructive'
                                : 'text-muted-foreground'
                          }`}
                        >
                          {c.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-md">
                        {c.evidence && c.evidence.length > 0 ? (
                          <ul className="space-y-1">
                            {c.evidence.map((ev, i) => (
                              <li key={i} className="text-xs text-foreground flex gap-1.5">
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
          <Card className="border border-dashed">
            <CardContent className="flex flex-col items-center justify-center gap-2 py-12 text-center">
              <ShieldAlert className="w-8 h-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                {assessmentError
                  ? `Could not load the assessment: ${assessmentError}`
                  : 'No compliance frameworks available.'}
              </p>
            </CardContent>
          </Card>
        )
      )}
    </div>
  )
}
