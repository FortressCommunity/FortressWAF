'use client'

import * as React from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  LayoutDashboard, Globe, Shield, ScrollText, ShieldCheck,
  Menu, X, Sun, Moon, ChevronDown, LogOut,
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
const navItems = [
  { label: 'Overview', href: '/dashboard', icon: <LayoutDashboard className="w-4 h-4" /> },
  { label: 'Sites', href: '/dashboard/sites', icon: <Globe className="w-4 h-4" /> },
  { label: 'Detection', href: '/dashboard/rules', icon: <Shield className="w-4 h-4" /> },
  { label: 'Audit', href: '/dashboard/audit', icon: <ScrollText className="w-4 h-4" /> },
  { label: 'Compliance', href: '/dashboard/compliance', icon: <ShieldCheck className="w-4 h-4" /> },
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

  React.useEffect(() => {
    api.auth.me().then(setUser).catch(() => setUser(null))
  }, [])

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

        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-2 scrollbar-thin">
          {navItems.map((item) => {
            const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href))
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setSidebarOpen(false)}
                aria-current={isActive ? 'page' : undefined}
                className={cn(
                  'flex items-center gap-3 rounded-control px-3 py-2 text-sm transition-colors duration-150',
                  isActive
                    ? 'bg-primary/15 text-primary font-medium'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                )}
              >
                {item.icon}
                {item.label}
              </Link>
            )
          })}
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
        <header className="glass-chrome sticky top-0 z-30 flex items-center gap-4 px-4 h-16 border-b border-border">
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

        <main className="p-6">
          {children}
        </main>
      </div>
    </div>
  )
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return <DashboardShell>{children}</DashboardShell>
}
