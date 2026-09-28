'use client'

import { Globe, ShieldAlert } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { api } from '@/lib/api'
import { usePolling } from '@/lib/use-polling'

export default function SitesPage() {
  const { data, loading, error, reload } = usePolling(() => api.sites(), 10_000)
  const sites = data?.sites ?? []

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-foreground">Sites</h1>
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
        <h1 className="text-2xl font-semibold text-foreground">Sites</h1>
        <p className="text-sm text-muted-foreground">
          Protected sites loaded from the running config
        </p>
      </div>

      {loading && sites.length === 0 ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {Array.from({ length: 2 }).map((_, i) => (
            <Skeleton key={i} className="h-44" />
          ))}
        </div>
      ) : sites.length === 0 ? (
        <Card className="border border-dashed">
          <CardContent className="flex flex-col items-center justify-center gap-2 py-12 text-center">
            <Globe className="w-8 h-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              No sites configured. Add one under <span className="font-mono">sites:</span> in the config file.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {sites.map((site) => (
            <Card key={site.name}>
              <CardHeader className="flex flex-row items-start justify-between">
                <div>
                  <CardTitle className="font-semibold text-foreground">
                    {site.name}
                  </CardTitle>
                  <p className="text-xs text-muted-foreground font-mono mt-1">
                    {site.domains.join(', ') || 'no domains'}
                  </p>
                </div>
                <Badge
                  variant="outline"
                  className={`font-medium ${
                    site.waf_enabled
                      ? 'border-primary text-primary'
                      : 'text-muted-foreground'
                  }`}
                >
                  {site.waf_enabled ? 'WAF on' : 'WAF off'}
                </Badge>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <span className="text-xs font-semibold text-muted-foreground">Upstream</span>
                  <p className="text-sm font-mono text-foreground break-all">
                    {site.upstream}
                  </p>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <Badge variant="outline" className="text-muted-foreground">
                    TLS {site.tls ? 'on' : 'off'}
                  </Badge>
                  <Badge variant="outline" className="text-muted-foreground">
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
