'use client'

import * as React from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  LayoutDashboard, Globe, Shield, ScrollText, ShieldCheck, Radio, Bell, BarChart3, Settings2,
  Ban, Menu, X, Sun, Moon, ChevronDown, LogOut,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useTheme } from '@/components/theme-provider'
import { useToast } from '@/components/ui/toast'
import { cn } from '@/lib/utils'
import { api, setToken } from '@/lib/api'
import type { User } from '@/types'

// Only pages backed by a real endpoint. The previous nav linked to logs,
// patches, settings and admin pages whose routes were never implemented.
// Grouped by what an operator is doing: watching (live), triaging (alerts),
// understanding (analytics), and configuring (system).
const navGroups: Array<{ label: string; items: Array<{ label: string; href: string; icon: React.ReactNode }> }> = [
  {
    label: 'Monitor',
    items: [
      { label: 'Overview', href: '/dashboard', icon: <LayoutDashboard className="w-4 h-4" /> },
      { label: 'Live traffic', href: '/dashboard/traffic', icon: <Radio className="w-4 h-4" /> },
      { label: 'Alerts', href: '/dashboard/alerts', icon: <Bell className="w-4 h-4" /> },
      { label: 'Analytics', href: '/dashboard/analytics', icon: <BarChart3 className="w-4 h-4" /> },
      { label: 'IP bans', href: '/dashboard/bans', icon: <Ban className="w-4 h-4" /> },
    ],
  },
  {
    label: 'Configure',
    items: [
      { label: 'Detection', href: '/dashboard/rules', icon: <Shield className="w-4 h-4" /> },
      { label: 'Domains', href: '/dashboard/sites', icon: <Globe className="w-4 h-4" /> },
      { label: 'Audit trail', href: '/dashboard/audit', icon: <ScrollText className="w-4 h-4" /> },
      { label: 'Compliance', href: '/dashboard/compliance', icon: <ShieldCheck className="w-4 h-4" /> },
      { label: 'System', href: '/dashboard/system', icon: <Settings2 className="w-4 h-4" /> },
    ],
  },
]

function Avatar({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-full bg-secondary', className)}>
      {children}
    </div>
  )
}

function AvatarFallback({ children }: { children: React.ReactNode }) {
  return (
    <span className="text-xs font-medium text-secondary-foreground">{children}</span>
  )
}

function DashboardShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const { theme, setTheme } = useTheme()
  const { toast } = useToast()
  const [sidebarOpen, setSidebarOpen] = React.useState(false)
  const [user, setUser] = React.useState<User | null>(null)
  const [unacked, setUnacked] = React.useState(0)

  React.useEffect(() => {
    api.auth.me().then(setUser).catch(() => setUser(null))
  }, [])

  // Poll the unacknowledged alert count so the sidebar shows live triage load.
  React.useEffect(() => {
    let alive = true
    const load = () => {
      api.alerts.list().then((a) => {
        if (alive) setUnacked(a.unacked)
      }).catch(() => {})
    }
    load()
    const id = setInterval(load, 5000)
    return () => { alive = false; clearInterval(id) }
  }, [pathname])

  function handleLogout() {
    setToken(null)
    toast({ title: 'Signed out', description: 'You have been signed out.' })
    router.push('/')
  }

  return (
    <div className="flex min-h-screen">
      <aside
        className={cn(
          'glass-chrome fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-border transition-transform duration-200 ease-out lg:sticky lg:top-0 lg:z-auto lg:h-screen lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex h-16 shrink-0 items-center gap-2.5 px-5">
          <div className="flex items-center justify-center w-8 h-8 rounded-control bg-primary">
            <Shield className="w-4 h-4 text-primary-foreground" />
          </div>
          <span className="font-semibold tracking-tight text-foreground">FortressWAF</span>
        </div>

        <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-3 scrollbar-thin">
          {navGroups.map((group) => (
            <div key={group.label}>
              <p className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                {group.label}
              </p>
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href))
                  const badgeCount = item.href === '/dashboard/alerts' ? unacked : 0
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={() => setSidebarOpen(false)}
                      aria-current={isActive ? 'page' : undefined}
                      className={cn(
                        'flex items-center gap-3 rounded-control px-3 py-2 text-sm transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60',
                        isActive
                          ? 'bg-primary/15 text-primary font-medium'
                          : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                      )}
                    >
                      {item.icon}
                      <span className="flex-1">{item.label}</span>
                      {badgeCount > 0 && (
                        <span className="inline-flex min-w-[1.25rem] items-center justify-center rounded-full bg-destructive px-1.5 text-[10px] font-semibold tabular-nums text-destructive-foreground">
                          {badgeCount > 99 ? '99+' : badgeCount}
                        </span>
                      )}
                    </Link>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="shrink-0 border-t border-border p-3">
          <div className="flex items-center gap-3 px-1 py-1">
            <Avatar>
              <AvatarFallback>{user?.name?.slice(0, 2).toUpperCase() ?? '—'}</AvatarFallback>
            </Avatar>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-foreground truncate">{user?.name ?? 'Admin'}</p>
              <p className="text-xs text-muted-foreground truncate font-mono">{user?.email ?? ''}</p>
            </div>
          </div>
        </div>
      </aside>

      {sidebarOpen && (
        <div className="fixed inset-0 z-40 bg-background/70 backdrop-blur-sm lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="glass-chrome sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border px-3 sm:h-16 sm:gap-4 sm:px-4">
          <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Toggle navigation" onClick={() => setSidebarOpen(!sidebarOpen)}>
            {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </Button>

          <span className="font-semibold text-sm tracking-tight text-foreground sm:hidden">
            FortressWAF
          </span>

          <div className="flex items-center gap-1 ml-auto">
            <Button
              variant="ghost"
              size="icon"
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            >
              {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </Button>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="flex items-center gap-2 px-1.5">
                  <Avatar>
                    <AvatarFallback>{user?.name?.slice(0, 2).toUpperCase() ?? '—'}</AvatarFallback>
                  </Avatar>
                  <ChevronDown className="w-4 h-4 text-muted-foreground hidden sm:block" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel>Signed in as {user?.email ?? 'admin'}</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleLogout} className="text-destructive focus:text-destructive">
                  <LogOut className="w-4 h-4 mr-2" /> Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <main className="min-w-0 p-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] sm:p-5 lg:p-6">
          {children}
        </main>
      </div>
    </div>
  )
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return <DashboardShell>{children}</DashboardShell>
}
