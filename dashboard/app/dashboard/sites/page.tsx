'use client'

import * as React from 'react'
import { Globe, Plus, Trash2, ShieldCheck, ShieldAlert, RefreshCw, Loader2 } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { useToast } from '@/components/ui/toast'
import { api, ApiError } from '@/lib/api'
import { usePolling } from '@/lib/use-polling'
import type { DomainsResponse, DomainAddError } from '@/types'

export default function DomainsPage() {
  const { toast } = useToast()
  const { data, loading, error, reload } = usePolling<DomainsResponse>(() => api.domains.list(), 8_000)

  const [domain, setDomain] = React.useState('')
  const [upstream, setUpstream] = React.useState('')
  const [adding, setAdding] = React.useState(false)
  const [addError, setAddError] = React.useState<DomainAddError | null>(null)
  const [busy, setBusy] = React.useState<string | null>(null)

  const domains = data?.domains ?? []
  const expectedIPs = data?.expected_ips ?? []

  async function add(e: React.FormEvent) {
    e.preventDefault()
    setAddError(null)
    if (!domain.trim()) return
    setAdding(true)
    try {
      await api.domains.add({ domain: domain.trim(), upstream: upstream.trim() || undefined })
      toast({ title: 'Domain added', description: `${domain.trim()} is now protected.`, variant: 'success' })
      setDomain('')
      setUpstream('')
      reload()
    } catch (err) {
      // A 422 carries the DNS detail the operator needs to fix the record.
      if (err instanceof ApiError) {
        try {
          const parsed = JSON.parse(err.message) as DomainAddError
          setAddError(parsed)
        } catch {
          setAddError({ error: err.message, domain: domain.trim(), resolved_ips: null, expected_ips: expectedIPs })
        }
      } else {
        setAddError({ error: 'Could not add domain', domain: domain.trim(), resolved_ips: null, expected_ips: expectedIPs })
      }
    } finally {
      setAdding(false)
    }
  }

  async function remove(d: string) {
    setBusy(d)
    try {
      await api.domains.remove(d)
      toast({ title: 'Domain removed', description: `${d} is no longer protected.` })
      reload()
    } catch (err) {
      toast({ title: 'Remove failed', description: err instanceof ApiError ? err.message : 'Try again.' })
    } finally {
      setBusy(null)
    }
  }

  async function recheck(d: string) {
    setBusy(d)
    try {
      const res = await api.domains.verify(d)
      toast({
        title: res.verified ? 'DNS verified' : 'DNS check failed',
        description: res.reason,
        variant: res.verified ? 'success' : 'destructive',
      })
      reload()
    } catch (err) {
      toast({ title: 'Check failed', description: err instanceof ApiError ? err.message : 'Try again.' })
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Protected domains</h1>
        <p className="text-sm text-muted-foreground">
          A domain is only protected after its DNS is verified to point here
        </p>
      </div>

      {/* Add form */}
      <Card>
        <CardContent className="p-4">
          <form onSubmit={add} className="flex flex-wrap items-end gap-2">
            <div className="min-w-[220px] flex-1">
              <label htmlFor="domain" className="mb-1 block text-xs font-medium text-muted-foreground">
                Domain
              </label>
              <Input
                id="domain"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="shop.example.com"
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <div className="min-w-[220px] flex-1">
              <label htmlFor="upstream" className="mb-1 block text-xs font-medium text-muted-foreground">
                Upstream <span className="text-muted-foreground/60">(optional, defaults to the first site)</span>
              </label>
              <Input
                id="upstream"
                value={upstream}
                onChange={(e) => setUpstream(e.target.value)}
                placeholder="http://backend:80"
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <Button type="submit" disabled={adding || !domain.trim()}>
              {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              Add &amp; verify
            </Button>
          </form>

          {expectedIPs.length > 0 ? (
            <p className="mt-3 text-xs text-muted-foreground">
              The domain must resolve to one of: <span className="font-mono text-foreground">{expectedIPs.join(', ')}</span>
            </p>
          ) : (
            <p className="mt-3 text-xs text-muted-foreground">
              No <span className="font-mono">server.expected_ips</span> configured — verification only checks that the domain resolves.
            </p>
          )}

          {addError && (
            <div className="mt-3 rounded-control border border-destructive/40 bg-destructive/5 p-3 text-xs">
              <p className="font-medium text-destructive">{addError.error}</p>
              {addError.resolved_ips && addError.resolved_ips.length > 0 && (
                <p className="mt-1 text-muted-foreground">
                  Resolved to: <span className="font-mono">{addError.resolved_ips.join(', ')}</span>
                </p>
              )}
              {addError.expected_ips && addError.expected_ips.length > 0 && (
                <p className="text-muted-foreground">
                  Expected: <span className="font-mono">{addError.expected_ips.join(', ')}</span>
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* List */}
      {error ? (
        <Card className="border border-destructive/40">
          <CardContent className="flex flex-col items-center gap-3 py-10 text-center">
            <ShieldAlert className="h-9 w-9 text-destructive" />
            <p className="max-w-md text-sm text-muted-foreground">{error}</p>
            <Button variant="outline" onClick={() => reload()}>Try again</Button>
          </CardContent>
        </Card>
      ) : loading && domains.length === 0 ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}
        </div>
      ) : domains.length === 0 ? (
        <Card className="border border-dashed">
          <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
            <Globe className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No protected domains yet. Add one above.</p>
          </CardContent>
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto overflow-y-auto scrollbar-thin">
            <table className="w-full text-left">
              <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                <tr className="border-b border-border text-[11px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-3 py-2 font-medium">Domain</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Resolves to</th>
                  <th className="px-3 py-2 font-medium">Upstream</th>
                  <th className="px-3 py-2 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {domains.map((d) => (
                  <tr key={d.domain} className="border-b border-border/60 text-sm">
                    <td className="px-3 py-2 font-mono text-xs text-foreground">{d.domain}</td>
                    <td className="px-3 py-2">
                      {d.verified ? (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-primary">
                          <ShieldCheck className="h-3.5 w-3.5" /> verified
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-warning">
                          <ShieldAlert className="h-3.5 w-3.5" /> unverified
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">
                      {d.resolved_ips && d.resolved_ips.length > 0 ? d.resolved_ips.join(', ') : '—'}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{d.upstream || '—'}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={busy === d.domain}
                          onClick={() => recheck(d.domain)}
                          aria-label={`Re-check DNS for ${d.domain}`}
                        >
                          <RefreshCw className={`h-3.5 w-3.5 ${busy === d.domain ? 'animate-spin' : ''}`} />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          disabled={busy === d.domain}
                          onClick={() => remove(d.domain)}
                          aria-label={`Remove ${d.domain}`}
                        >
                          <Trash2 className="h-4 w-4 text-muted-foreground" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}
