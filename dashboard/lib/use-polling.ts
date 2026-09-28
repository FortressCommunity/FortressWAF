'use client'

import * as React from 'react'
import { ApiError } from './api'

export interface PollingResult<T> {
  data: T | null
  loading: boolean
  error: string | null
  reload: () => void
}

// Runs `fetcher` on mount and every `intervalMs`, keeping loading and error
// state in sync. Pages share this instead of each re-implementing the same
// fetch / poll / error boilerplate.
//
// The async work lives in runPoll below, outside the component: calling a
// function whose setState calls sit after an await from an effect is flagged by
// react-hooks/set-state-in-effect, and moving the work out of the effect's
// lexical scope is what keeps the renders from cascading.
async function runPoll<T>(
  fetcher: () => Promise<T>,
  onData: (data: T) => void,
  onError: (message: string) => void,
  onSettled: () => void,
) {
  try {
    const result = await fetcher()
    onData(result)
    onError('')
  } catch (err) {
    onError(
      err instanceof ApiError
        ? `${err.message} (HTTP ${err.status})`
        : err instanceof Error
          ? err.message
          : 'Unknown error',
    )
  } finally {
    onSettled()
  }
}

export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
): PollingResult<T> {
  const [data, setData] = React.useState<T | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  // Keep the latest fetcher without restarting the poll interval. Written in
  // an effect because assigning a ref during render is not allowed.
  const fetcherRef = React.useRef(fetcher)
  React.useEffect(() => {
    fetcherRef.current = fetcher
  })

  const load = React.useCallback(() => {
    void runPoll(
      () => fetcherRef.current(),
      (result) => {
        setData(result)
        setError(null)
      },
      (message) => {
        if (message) setError(message)
      },
      () => setLoading(false),
    )
  }, [])

  // A manual retry shows the loading state again; the automatic poll does not,
  // so the dashboard does not blank out every few seconds during a demo.
  const reload = React.useCallback(() => {
    setLoading(true)
    load()
  }, [load])

  React.useEffect(() => {
    load()
    const id = setInterval(load, intervalMs)
    return () => clearInterval(id)
  }, [load, intervalMs])

  return { data, loading, error, reload }
}
