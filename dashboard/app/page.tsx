'use client'

import * as React from 'react'
import { Shield, Eye, EyeOff, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useToast } from '@/components/ui/toast'
import { api, setToken } from '@/lib/api'
import { useRouter } from 'next/navigation'

export default function LoginPage() {
  const router = useRouter()
  const { toast } = useToast()
  const [showPassword, setShowPassword] = React.useState(false)
  const [isLoading, setIsLoading] = React.useState(false)
  const [email, setEmail] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [error, setError] = React.useState('')

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault()
    if (!email || !password) {
      setError('Email and password are required')
      return
    }
    setError('')
    setIsLoading(true)
    try {
      const response = await api.auth.login(email, password)
      setToken(response.token)
      toast({ title: 'Welcome back!', description: 'Redirecting to dashboard...', variant: 'success' })
      window.location.href = '/dashboard'
    } catch (err: unknown) {
      const errorObj = err as { message?: string }
      toast({ title: 'Login failed', description: errorObj.message || 'Invalid credentials', variant: 'destructive' })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="w-full max-w-md px-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 border-2 border-foreground bg-primary shadow-brutal mb-4">
            <Shield className="w-8 h-8 text-primary-foreground" />
          </div>
          <h1 className="text-3xl font-black text-foreground uppercase tracking-tight">FortressWAF</h1>
          <p className="text-muted-foreground font-bold mt-1">Web Application Firewall · admin console</p>
        </div>

        <div className="border-2 border-foreground bg-card p-8 shadow-brutal-lg">
          <form onSubmit={handleLogin} className="space-y-5">
            <div>
              <label htmlFor="email" className="block text-sm font-bold text-foreground mb-1.5">
                Email address
              </label>
              <Input
                id="email"
                type="email"
                autoComplete="username"
                placeholder="admin@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-bold text-foreground mb-1.5">
                Password
              </label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder="Password"
                  className="pr-10"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {error && <p className="text-destructive text-xs font-bold">{error}</p>}

            <p className="text-xs text-muted-foreground font-medium">
              Sign in with any key listed under <span className="font-mono">admin.api_keys</span> in the config file.
            </p>

            <Button
              type="submit"
              disabled={isLoading}
              className="w-full"
            >
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
              Sign in
            </Button>
          </form>

        </div>

        <p className="text-center text-xs font-bold text-muted-foreground mt-6">
          &copy; {new Date().getFullYear()} FortressWAF. All rights reserved.
        </p>
      </div>
    </div>
  )
}
