'use client'

import * as React from 'react'
import { Shield, ShieldAlert } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { api, ApiError } from '@/lib/api'
import type { Inspector, ConfigRule } from '@/types'

// What each inspector actually looks for, so the table reads as more than
// a list of internal module names. Descriptions match the rule sets in
// internal/engine.
const DESCRIPTIONS: Record<string, string> = {
  sqli: 'SQL injection: tautologies, UNION, stacked queries, blind/time-based, encoded bypass',
  xss: 'Cross-site scripting: script tags, event handlers, attribute and obfuscated payloads',
  rce: 'Command injection, SSTI, EL injection, deserialization gadgets, Log4Shell, file inclusion',
  parser_hardener: 'Parser hardening: encoding abuse, null bytes, malformed request structure',
  desync: 'HTTP request smuggling: CL.TE and TE.CL desync',
  ja3: 'JA3 TLS fingerprinting of known scanners and bots (TLS traffic only)',
  bot_detector: 'Bot detection against a signature list (includes curl)',
  ddos_protection: 'Slow loris and slow POST detection',
  api_protection: 'API protection: mass assignment and schema hints',
  protocol_anomaly: 'Protocol anomalies: verb tampering, header smuggling, malformed requests',
  file_upload: 'Upload validation: MIME signature, extension allow/block, magic bytes',
  credential_protection: 'Credential protection: brute force, stuffing, spray, lockout',
}

export default function RulesPage() {
  const [inspectors, setInspectors] = React.useState<Inspector[]>([])
  const [rules, setRules] = React.useState<ConfigRule[]>([])
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  const load = React.useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [insp, cfgRules] = await Promise.all([api.inspectors(), api.rules()])
      setInspectors(insp.inspectors)
      setRules(cfgRules.rules)
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

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-black uppercase tracking-tight text-foreground">Detection</h1>
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

  const totalHits = inspectors.reduce((sum, i) => sum + i.hits, 0)
  const sorted = [...inspectors].sort((a, b) => b.hits - a.hits)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-black uppercase tracking-tight text-foreground">Detection</h1>
        <p className="text-sm text-muted-foreground font-bold">
          Built-in detection modules registered in the running engine · {totalHits} hits in the audit log
        </p>
      </div>

      {loading && inspectors.length === 0 ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-36 border-2 border-foreground/20" />
          ))}
        </div>
      ) : sorted.length === 0 ? (
        <Card className="border-2 border-dashed border-foreground/40">
          <CardContent className="flex flex-col items-center justify-center gap-2 py-12 text-center">
            <Shield className="w-8 h-8 text-muted-foreground" />
            <p className="text-sm font-bold text-muted-foreground">
              No inspectors registered. Enable modules in the config file.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {sorted.map((ins) => (
            <Card key={ins.name} className="border-2 border-foreground shadow-brutal">
              <CardHeader className="flex flex-row items-start justify-between">
                <CardTitle className="font-mono text-sm font-black uppercase tracking-tight text-foreground">
                  {ins.name}
                </CardTitle>
                <Badge
                  variant="outline"
                  className={`border-2 font-black uppercase shrink-0 ${
                    ins.enabled
                      ? 'border-primary text-primary'
                      : 'border-foreground/40 text-muted-foreground'
                  }`}
                >
                  {ins.enabled ? 'on' : 'off'}
                </Badge>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-muted-foreground font-medium min-h-[2.5rem]">
                  {DESCRIPTIONS[ins.name] || 'Detection module registered in the engine.'}
                </p>
                <div className="mt-4 flex items-baseline gap-2 border-t-2 border-foreground/10 pt-3">
                  <span className="text-2xl font-black text-foreground tabular-nums">{ins.hits}</span>
                  <span className="text-xs font-bold uppercase text-muted-foreground">
                    {ins.hits === 1 ? 'hit' : 'hits'}
                  </span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Card className="border-2 border-foreground shadow-brutal">
        <CardHeader>
          <CardTitle className="text-sm font-black uppercase tracking-tight">
            Rules from the config file
          </CardTitle>
          <p className="text-xs text-muted-foreground font-medium">
            Rules are not loaded from disk in the current build; this section is empty by
            default and reports whatever the config defines.
          </p>
        </CardHeader>
        <CardContent>
          {rules.length === 0 ? (
            <p className="text-sm font-bold text-muted-foreground py-4">
              No custom rules configured. Detection runs entirely on the built-in modules above.
            </p>
          ) : (
            <div className="overflow-x-auto scrollbar-thin">
              <table className="w-full">
                <thead>
                  <tr className="border-b-2 border-foreground">
                    <th className="text-left py-2 font-black uppercase text-xs">ID</th>
                    <th className="text-left py-2 font-black uppercase text-xs">Name</th>
                    <th className="text-left py-2 font-black uppercase text-xs">Severity</th>
                    <th className="text-left py-2 font-black uppercase text-xs">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.id} className="border-b border-foreground/30">
                      <td className="py-2 font-mono text-xs font-bold">{r.id}</td>
                      <td className="py-2 text-xs font-medium">{r.name}</td>
                      <td className="py-2 text-xs font-mono">{r.severity}</td>
                      <td className="py-2 text-xs font-bold">{r.enabled ? 'enabled' : 'disabled'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
