import { NextRequest, NextResponse } from 'next/server'

// Public paths that don't require authentication
const publicPaths = [
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/password-reset',
  '/api/health',
]

// Static assets and Next.js internals
const ignoredPaths = [
  '/_next',
  '/favicon.ico',
  '/api/auth/set',
  '/api/auth/cookie',
  '/__/auth',
]

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Skip middleware for static assets and internals
  if (ignoredPaths.some(path => pathname.startsWith(path))) {
    return NextResponse.next()
  }

  // Check if path is public
  const isPublicPath = publicPaths.some(path => pathname.startsWith(path))

  // Get auth token from cookies
  const authToken = request.cookies.get('auth_token')?.value
  const hasAuth = !!authToken

  // Redirect logic
  if (pathname === '/') {
    // Root path - redirect based on auth status
    if (!hasAuth) {
      return NextResponse.redirect(new URL('/login', request.url))
    }
    return NextResponse.redirect(new URL('/qa-dashboard', request.url))
  }

  // Redirect authenticated users away from auth pages
  if (hasAuth && isPublicPath) {
    return NextResponse.redirect(new URL('/qa-dashboard', request.url))
  }

  // Redirect unauthenticated users to login
  if (!hasAuth && !isPublicPath) {
    const loginUrl = new URL('/login', request.url)
    loginUrl.searchParams.set('redirect', pathname)
    return NextResponse.redirect(loginUrl)
  }

  // Add auth header for API routes if token exists
  if (pathname.startsWith('/api/') && hasAuth) {
    const requestHeaders = new Headers(request.headers)
    requestHeaders.set('Authorization', `Bearer ${authToken}`)
    
    return NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    })
  }

  return NextResponse.next()
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api/auth (auth endpoints)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    '/((?!api/auth|_next/static|_next/image|favicon.ico|public).*)',
  ],
}
