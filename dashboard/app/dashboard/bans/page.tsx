'use client'

import * as React from 'react'
import { Ban as BanIcon, Plus, ShieldAlert, Loader2, ShieldCheck } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { useToast } from '@/components/ui/toast'
import { api, ApiError } from '@/lib/api'
import { usePolling } from '@/lib/use-polling'
import { formatDate } from '@/lib/utils'
import type { BansResponse } from '@/types'

const PRESETS = [
  { label: '1 hour', seconds: 3600 },
  { label: '24 hours', seconds: 86400 },
  { label: '7 days', seconds: 604800 },
  { label: 'Permanent', seconds: 0 },
]

export default function BansPage() {
  const { toast } = useToast()
  const { data, loading, error, reload } = usePolling<BansResponse>(() => api.bans.list(), 5_000)

  const [ip, setIP] = React.useState('')
  const [reason, setReason] = React.useState('')
  const [ttl, setTTL] = React.useState(86400)
  const [adding, setAdding] = React.useState(false)
  const [busy, setBusy] = React.useState<string | null>(null)

  const bans = data?.bans ?? []

  async function ban(e: React.FormEvent) {
    e.preventDefault()
    if (!ip.trim()) return
    setAdding(true)
    try {
      await api.bans.add({ ip: ip.trim(), reason: reason.trim(), ttl_seconds: ttl })
      toast({ title: 'IP banned', description: `${ip.trim()} is now blocked at the WAF.`, variant: 'success' })
      setIP('')
      setReason('')
      reload()
    } catch (err) {
      toast({ title: 'Ban failed', description: err instanceof ApiError ? err.message : 'Enter a valid IPv4 or IPv6 address.' })
    } finally {
      setAdding(false)
    }
  }

  async function unban(address: string) {
    setBusy(address)
    try {
      await api.bans.remove(address)
      toast({ title: 'IP unbanned', description: `${address} can reach the site again.` })
      reload()
    } catch (err) {
      toast({ title: 'Unban failed', description: err instanceof ApiError ? err.message : 'Try again.' })
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-foreground">IP bans</h1>
        <p className="text-sm text-muted-foreground">
          Banned addresses are refused before inspection, on every protected site
        </p>
      </div>

      <Card>
        <CardContent className="p-4">
          <form onSubmit={ban} className="flex flex-wrap items-end gap-2">
            <div className="min-w-[180px] flex-1">
              <label htmlFor="ip" className="mb-1 block text-xs font-medium text-muted-foreground">IP address</label>
              <Input id="ip" value={ip} onChange={(e) => setIP(e.target.value)} placeholder="203.0.113.7" autoComplete="off" spellCheck={false} />
            </div>
            <div className="min-w-[200px] flex-1">
              <label htmlFor="reason" className="mb-1 block text-xs font-medium text-muted-foreground">Reason (optional)</label>
              <Input id="reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Brute-force attempts" autoComplete="off" />
            </div>
            <div>
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Duration</span>
              <div className="flex items-center gap-1 overflow-x-auto rounded-control border border-border p-0.5 scrollbar-thin">
                {PRESETS.map((p) => (
                  <button
                    key={p.label}
                    type="button"
                    onClick={() => setTTL(p.seconds)}
                    aria-pressed={ttl === p.seconds}
                    className={`shrink-0 rounded-control px-2.5 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 ${
                      ttl === p.seconds ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
            <Button type="submit" disabled={adding || !ip.trim()}>
              {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              Ban
            </Button>
          </form>
        </CardContent>
      </Card>

      {error ? (
        <Card className="border border-destructive/40">
          <CardContent className="flex flex-col items-center gap-3 py-10 text-center">
            <ShieldAlert className="h-9 w-9 text-destructive" />
            <p className="max-w-md text-sm text-muted-foreground">{error}</p>
            <Button variant="outline" onClick={() => reload()}>Try again</Button>
          </CardContent>
        </Card>
      ) : loading && bans.length === 0 ? (
        <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)}</div>
      ) : bans.length === 0 ? (
        <Card className="border border-dashed">
          <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
            <ShieldCheck className="h-8 w-8 text-primary" />
            <p className="text-sm text-muted-foreground">No banned addresses.</p>
          </CardContent>
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto overflow-y-auto scrollbar-thin">
            <table className="w-full text-left">
              <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                <tr className="border-b border-border text-[11px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-3 py-2 font-medium">IP</th>
                  <th className="px-3 py-2 font-medium">Reason</th>
                  <th className="px-3 py-2 font-medium">Banned at</th>
                  <th className="px-3 py-2 font-medium">Expires</th>
                  <th className="px-3 py-2 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {bans.map((b) => (
                  <tr key={b.ip} className="border-b border-border/60 text-sm">
                    <td className="px-3 py-2 font-mono text-xs text-foreground">{b.ip}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{b.reason || '—'}</td>
                    <td className="px-3 py-2 font-mono text-[11px] tabular-nums text-muted-foreground">{formatDate(b.created_at)}</td>
                    <td className="px-3 py-2 font-mono text-[11px] tabular-nums text-muted-foreground">
                      {b.permanent ? 'permanent' : formatDate(b.expires_at)}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={busy === b.ip}
                        onClick={() => unban(b.ip)}
                        aria-label={`Unban ${b.ip}`}
                      >
                        <BanIcon className="h-3.5 w-3.5" /> Unban
                      </Button>
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
