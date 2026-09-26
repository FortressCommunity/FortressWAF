'use client'

import * as React from 'react'
import { Globe, ShieldAlert } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { api, ApiError } from '@/lib/api'
import type { Site } from '@/types'

export default function SitesPage() {
  const [sites, setSites] = React.useState<Site[]>([])
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  const load = React.useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.sites()
      setSites(res.sites)
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
    const id = setInterval(load, 10000)
    return () => clearInterval(id)
  }, [load])

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-black uppercase tracking-tight text-foreground">Sites</h1>
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
        <h1 className="text-2xl font-black uppercase tracking-tight text-foreground">Sites</h1>
        <p className="text-sm text-muted-foreground font-bold">
          Protected sites loaded from the running config
        </p>
      </div>

      {loading && sites.length === 0 ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {Array.from({ length: 2 }).map((_, i) => (
            <Skeleton key={i} className="h-44 border-2 border-foreground/20" />
          ))}
        </div>
      ) : sites.length === 0 ? (
        <Card className="border-2 border-dashed border-foreground/40">
          <CardContent className="flex flex-col items-center justify-center gap-2 py-12 text-center">
            <Globe className="w-8 h-8 text-muted-foreground" />
            <p className="text-sm font-bold text-muted-foreground">
              No sites configured. Add one under <span className="font-mono">sites:</span> in the config file.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {sites.map((site) => (
            <Card key={site.name} className="border-2 border-foreground shadow-brutal">
              <CardHeader className="flex flex-row items-start justify-between">
                <div>
                  <CardTitle className="font-black uppercase tracking-tight text-foreground">
                    {site.name}
                  </CardTitle>
                  <p className="text-xs text-muted-foreground font-medium font-mono mt-1">
                    {site.domains.join(', ') || 'no domains'}
                  </p>
                </div>
                <Badge
                  variant="outline"
                  className={`border-2 font-black uppercase ${
                    site.waf_enabled
                      ? 'border-primary text-primary'
                      : 'border-foreground/40 text-muted-foreground'
                  }`}
                >
                  {site.waf_enabled ? 'WAF on' : 'WAF off'}
                </Badge>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <span className="text-xs font-black uppercase text-muted-foreground">Upstream</span>
                  <p className="text-sm font-mono text-foreground font-medium break-all">
                    {site.upstream}
                  </p>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <Badge variant="outline" className="border-2 border-foreground/40 text-muted-foreground font-bold">
                    TLS {site.tls ? 'on' : 'off'}
                  </Badge>
                  <Badge variant="outline" className="border-2 border-foreground/40 text-muted-foreground font-bold">
                    port {site.port || 80}
                  </Badge>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
