'use client'

import * as React from 'react'
import { ShieldAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'

// Route-level error boundary for the dashboard. Without one, an uncaught
// client error (a blocked storage API, a render bug) makes the browser show a
// "This page couldn't load" screen. This catches it and offers a retry, so a
// single failure does not take the whole route down.
export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <Card className="max-w-md border border-destructive/40">
        <CardContent className="flex flex-col items-center gap-3 py-10 text-center">
          <ShieldAlert className="h-10 w-10 text-destructive" />
          <div>
            <h1 className="font-semibold text-foreground">Something went wrong</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              This screen hit an error. You can retry; if it keeps failing, reload the page.
            </p>
            {error?.message && (
              <p className="mt-2 break-words font-mono text-[11px] text-muted-foreground/80">
                {error.message}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => reset()}>Try again</Button>
            <Button onClick={() => window.location.reload()}>Reload</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
