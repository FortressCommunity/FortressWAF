/** @type {import('next').NextConfig} */

// The admin API origin the browser calls. CSP connect-src must name it exactly;
// everything else is denied. NEXT_PUBLIC_API_URL is inlined at build time, so
// this stays in sync with lib/api.ts.
const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8443/api/v1'
let apiOrigin = apiUrl
try {
  apiOrigin = new URL(apiUrl).origin
} catch {
  // Leave as-is; a malformed URL will simply not match connect-src.
}

// Next.js injects inline bootstrap scripts, and the theme is applied by an
// inline script in layout.tsx, so 'unsafe-inline' is required for scripts. The
// rest is locked down: no remote script/frame/object sources, and network
// access limited to the admin API.
const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  `connect-src 'self' ${apiOrigin}`,
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join('; ')

const securityHeaders = [
  { key: 'Content-Security-Policy', value: csp },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains',
  },
]

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',

  // The dashboard serves no user-supplied images, so the built-in Image
  // Optimization API is not needed. Disabling it drops the sharp dependency,
  // whose bundled libvips carried two high and one critical advisory
  // (npm audit). Images are delivered as-is.
  images: {
    unoptimized: true,
  },

  // Security headers on every route. The dashboard holds an admin bearer
  // token, so a strict CSP (no remote script origins) is the control that
  // matters most: it removes the XSS path that would otherwise let a script
  // read the token out of localStorage.
  //
  // Cache policy matters too: the app router defaulted to caching the login
  // HTML for a year, so a browser (or Cloudflare) could serve a stale page whose
  // script chunks no longer exist after a deploy — the "This page couldn't
  // load" a phone shows when a cached HTML points at a deleted chunk. HTML is
  // therefore no-store, while the content-hashed /_next/static assets (whose
  // names change every build) cache immutably.
  async headers() {
    return [
      // HTML and route payloads must revalidate so a deploy is picked up. This
      // rule is listed FIRST so the more specific static rule below, which
      // matches later, wins for build output.
      {
        source: '/:path*',
        headers: [
          ...securityHeaders,
          { key: 'Cache-Control', value: 'no-store, must-revalidate' },
        ],
      },
      {
        // Content-hashed build output: safe to cache forever. Listed last so it
        // overrides the no-store rule above for /_next/static.
        source: '/_next/static/:path*',
        headers: [
          { key: 'Cache-Control', value: 'public, max-age=31536000, immutable' },
        ],
      },
    ]
  },
}

export default nextConfig
