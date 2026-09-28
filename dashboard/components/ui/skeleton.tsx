import * as React from 'react'
import { cn } from '@/lib/utils'

function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('animate-pulse rounded-control bg-muted', className)} {...props} />
}

function CardSkeleton() {
  return (
    <div className="glass rounded-panel p-5">
      <Skeleton className="h-3 w-[110px] mb-3" />
      <Skeleton className="h-7 w-[80px] mb-2" />
      <Skeleton className="h-3 w-[100px]" />
    </div>
  )
}

function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="glass rounded-panel overflow-hidden">
      <div className="flex gap-4 p-4 border-b border-border">
        <Skeleton className="h-3 flex-1" />
        <Skeleton className="h-3 flex-1" />
        <Skeleton className="h-3 flex-1" />
        <Skeleton className="h-3 flex-1" />
      </div>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4 p-4 border-b border-border last:border-b-0">
          <Skeleton className="h-3 flex-1" />
          <Skeleton className="h-3 flex-1" />
          <Skeleton className="h-3 flex-1" />
          <Skeleton className="h-3 flex-1" />
        </div>
      ))}
    </div>
  )
}

export { Skeleton, CardSkeleton, TableSkeleton }
