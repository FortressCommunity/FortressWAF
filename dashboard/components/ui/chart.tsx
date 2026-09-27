'use client'

import * as React from 'react'
import { cn } from '@/lib/utils'

interface ChartContainerProps {
  title?: string
  subtitle?: string
  className?: string
  children: React.ReactNode
}

// Panel that frames a chart or list. The overview page draws its charts with
// plain divs, so this is the only chart primitive in use.
function ChartContainer({ title, subtitle, className, children }: ChartContainerProps) {
  return (
    <div className={cn('glass rounded-panel p-5', className)}>
      {title && <h3 className="text-sm font-semibold text-foreground">{title}</h3>}
      {subtitle && <p className="text-xs text-muted-foreground mt-1 mb-4">{subtitle}</p>}
      {children}
    </div>
  )
}

export { ChartContainer }
