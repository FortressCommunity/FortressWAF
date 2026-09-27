import type { Metadata } from 'next'
import { IBM_Plex_Sans, IBM_Plex_Mono } from 'next/font/google'
import { ThemeProvider } from '@/components/theme-provider'
import { ToastProvider, ToastViewport } from '@/components/ui/toast'
import './globals.css'

// Plex for interface text, Plex Mono for machine data (rule IDs, IPs, hashes).
// Chosen over the Inter/Geist default because the mono is functional here, not
// decorative, and the pair reads as engineered rather than generic.
const plexSans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-plex-sans',
})
const plexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500'],
  variable: '--font-plex-mono',
})

export const metadata: Metadata = {
  title: 'FortressWAF — Admin console',
  description: 'Management dashboard for the FortressWAF reverse proxy',
}

// Applied before hydration so the correct colour scheme is painted on the first
// frame. Runs before React, so it must not depend on any React state and must
// keep its logic in sync with components/theme-provider.tsx.
const themeScript = `(function () {
  try {
    var t = localStorage.getItem('theme');
    var dark = t === 'dark' || t === 'system'
      ? matchMedia('(prefers-color-scheme: dark)').matches
      : t !== 'light';
    document.documentElement.classList.add(dark ? 'dark' : 'light');
  } catch (e) {}
})()`

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className={`${plexSans.variable} ${plexMono.variable} font-sans antialiased`}>
        <ThemeProvider defaultTheme="dark" enableSystem>
          <ToastProvider>
            {children}
            <ToastViewport />
          </ToastProvider>
        </ThemeProvider>
      </body>
    </html>
  )
}
