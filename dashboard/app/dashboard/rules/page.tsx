'use client'

import { Shield, ShieldAlert } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { api } from '@/lib/api'
import { usePolling } from '@/lib/use-polling'
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

interface RulesData {
  inspectors: Inspector[]
  rules: ConfigRule[]
}

export default function RulesPage() {
  const { data, loading, error, reload } = usePolling<RulesData>(async () => {
    const [insp, cfgRules] = await Promise.all([api.inspectors(), api.rules()])
    return {
      inspectors: insp?.inspectors ?? [],
      rules: cfgRules?.rules ?? [],
    }
  }, 5_000)

  const inspectors = data?.inspectors ?? []
  const rules = data?.rules ?? []

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-foreground">Detection</h1>
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

  const totalHits = inspectors.reduce((sum, i) => sum + i.hits, 0)
  const sorted = [...inspectors].sort((a, b) => b.hits - a.hits)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Detection</h1>
        <p className="text-sm text-muted-foreground">
          Built-in detection modules registered in the running engine · {totalHits} hits in the audit log
        </p>
      </div>

      {loading && inspectors.length === 0 ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-36" />
          ))}
        </div>
      ) : sorted.length === 0 ? (
        <Card className="border border-dashed">
          <CardContent className="flex flex-col items-center justify-center gap-2 py-12 text-center">
            <Shield className="w-8 h-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              No inspectors registered. Enable modules in the config file.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {sorted.map((ins) => (
            <Card key={ins.name}>
              <CardHeader className="flex flex-row items-start justify-between">
                <CardTitle className="font-mono text-sm font-semibold text-foreground">
                  {ins.name}
                </CardTitle>
                <Badge
                  variant="outline"
                  className={`font-medium shrink-0 ${
                    ins.enabled
                      ? 'border-primary text-primary'
                      : 'text-muted-foreground'
                  }`}
                >
                  {ins.enabled ? 'on' : 'off'}
                </Badge>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-muted-foreground min-h-[2.5rem]">
                  {DESCRIPTIONS[ins.name] || 'Detection module registered in the engine.'}
                </p>
                <div className="mt-4 flex items-baseline gap-2 border-t border-border pt-3">
                  <span className="text-2xl font-semibold text-foreground tabular-nums">{ins.hits}</span>
                  <span className="text-xs text-muted-foreground">
                    {ins.hits === 1 ? 'hit' : 'hits'}
                  </span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold">
            Rules from the config file
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Rules are not loaded from disk in the current build; this section is empty by
            default and reports whatever the config defines.
          </p>
        </CardHeader>
        <CardContent>
          {rules.length === 0 ? (
            <p className="text-sm text-muted-foreground py-4">
              No custom rules configured. Detection runs entirely on the built-in modules above.
            </p>
          ) : (
            <div className="max-h-96 overflow-x-auto overflow-y-auto scrollbar-thin">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="sticky top-0 bg-card py-2 text-left text-xs font-medium text-muted-foreground">ID</th>
                    <th className="sticky top-0 bg-card py-2 text-left text-xs font-medium text-muted-foreground">Name</th>
                    <th className="sticky top-0 bg-card py-2 text-left text-xs font-medium text-muted-foreground">Severity</th>
                    <th className="sticky top-0 bg-card py-2 text-left text-xs font-medium text-muted-foreground">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.id} className="border-b border-border">
                      <td className="py-2 font-mono text-xs">{r.id}</td>
                      <td className="py-2 text-xs">{r.name}</td>
                      <td className="py-2 text-xs font-mono">{r.severity}</td>
                      <td className="py-2 text-xs">{r.enabled ? 'enabled' : 'disabled'}</td>
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
