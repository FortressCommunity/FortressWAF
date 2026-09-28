'use client'

import * as React from 'react'
import { createContext, useContext, useEffect, useState, useSyncExternalStore } from 'react'

type Theme = 'dark' | 'light' | 'system'
type ResolvedTheme = 'dark' | 'light'

interface ThemeContextValue {
  theme: Theme
  setTheme: (theme: Theme) => void
  resolvedTheme: ResolvedTheme
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: 'dark',
  setTheme: () => {},
  resolvedTheme: 'dark',
})

const STORAGE_KEY = 'theme'

// The persisted theme lives in localStorage, i.e. outside React. Reading it in
// a mount effect and calling setState triggers a cascading render (flagged by
// react-hooks/set-state-in-effect), so the store is read with
// useSyncExternalStore instead: getServerSnapshot returns the default so the
// server-rendered HTML matches the first client render, and React then re-syncs
// to the persisted value without an extra render pass.
function subscribeToStorage(callback: () => void) {
  window.addEventListener('storage', callback)
  return () => window.removeEventListener('storage', callback)
}

function readStoredTheme(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored === 'light' || stored === 'dark' || stored === 'system') return stored
  return 'dark'
}

// 'system' follows the OS colour scheme, which can change while the page is
// open, so it is read from matchMedia rather than derived once.
function subscribeToColorScheme(callback: () => void) {
  const mq = window.matchMedia('(prefers-color-scheme: dark)')
  mq.addEventListener('change', callback)
  return () => mq.removeEventListener('change', callback)
}

function readColorScheme(): ResolvedTheme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function ThemeProvider({
  children,
  defaultTheme = 'dark',
  enableSystem = true,
}: {
  children: React.ReactNode
  defaultTheme?: Theme
  enableSystem?: boolean
}) {
  // In-tab toggle: overrides the persisted value until the page is reloaded.
  const [override, setOverride] = useState<Theme | null>(null)

  const stored = useSyncExternalStore(
    subscribeToStorage,
    readStoredTheme,
    // Server render and the first client render must agree to avoid a
    // hydration mismatch; the real value is picked up right after.
    () => defaultTheme,
  )

  const system = useSyncExternalStore(
    subscribeToColorScheme,
    readColorScheme,
    () => 'dark' as ResolvedTheme,
  )

  const theme = override ?? stored
  const resolvedTheme: ResolvedTheme =
    theme === 'system' && enableSystem ? system : (theme as ResolvedTheme)

  // Side effect only: sync the <html> class with the resolved theme. No state
  // is set here, so this cannot cause a cascading render.
  useEffect(() => {
    const root = document.documentElement
    root.classList.remove('light', 'dark')
    root.classList.add(resolvedTheme)
  }, [resolvedTheme])

  const setTheme = React.useCallback((t: Theme) => {
    setOverride(t)
    localStorage.setItem(STORAGE_KEY, t)
  }, [])

  return (
    <ThemeContext.Provider value={{ theme, setTheme, resolvedTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) throw new Error('useTheme must be used within a ThemeProvider')
  return context
}
