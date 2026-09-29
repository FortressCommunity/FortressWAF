'use client'

import * as React from 'react'

// App-level error boundary. A client crash anywhere renders this instead of the
// browser's generic "This page couldn't load" screen.
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: '#0d1117',
          color: '#e6edf3',
          fontFamily: 'system-ui, sans-serif',
        }}
      >
        <div style={{ maxWidth: 420, padding: 32, textAlign: 'center' }}>
          <h1 style={{ fontSize: 20, margin: '0 0 8px' }}>Something went wrong</h1>
          <p style={{ color: '#9da7b3', fontSize: 14, margin: '0 0 20px' }}>
            The console hit an unexpected error.
          </p>
          <button
            type="button"
            onClick={() => reset()}
            style={{
              padding: '8px 16px',
              borderRadius: 8,
              border: '1px solid #30363d',
              background: '#21262d',
              color: '#e6edf3',
              cursor: 'pointer',
            }}
          >
            Try again
          </button>
        </div>
      </body>
    </html>
  )
}
