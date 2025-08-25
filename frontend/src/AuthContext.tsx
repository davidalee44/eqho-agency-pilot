'use client'

import React, { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import axios from 'axios'

interface User {
  id: string
  email: string
  name: string
  roles: string[]
  organizations: string[]
  is_admin: boolean
  email_verified: boolean
}

interface AuthContextType {
  user: User | null
  loading: boolean
  error: string | null
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string, name: string) => Promise<void>
  logout: () => Promise<void>
  refreshToken: () => Promise<void>
  isAuthenticated: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

// API base URL
const API_URL = process.env.NEXT_PUBLIC_API_URL || '/api/v1'

// Token storage keys
const ACCESS_TOKEN_KEY = 'auth_token'
const REFRESH_TOKEN_KEY = 'refresh_token'

// Helper functions for token management
const getAccessToken = (): string | null => {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(ACCESS_TOKEN_KEY)
}

const getRefreshToken = (): string | null => {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(REFRESH_TOKEN_KEY)
}

const setTokens = (accessToken: string, refreshToken: string) => {
  localStorage.setItem(ACCESS_TOKEN_KEY, accessToken)
  localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
  
  // Also set cookies for SSR
  const isSecure = window.location.protocol === 'https:'
  const cookieFlags = `path=/; max-age=86400; SameSite=Lax${isSecure ? '; Secure' : ''}`
  document.cookie = `${ACCESS_TOKEN_KEY}=${accessToken}; ${cookieFlags}`
  document.cookie = `${REFRESH_TOKEN_KEY}=${refreshToken}; ${cookieFlags}`
}

const clearTokens = () => {
  localStorage.removeItem(ACCESS_TOKEN_KEY)
  localStorage.removeItem(REFRESH_TOKEN_KEY)
  
  // Clear cookies
  document.cookie = `${ACCESS_TOKEN_KEY}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`
  document.cookie = `${REFRESH_TOKEN_KEY}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`
}

// Create axios instance for auth requests
const authApi = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
})

// Add request interceptor to include auth token
authApi.interceptors.request.use(
  (config) => {
    const token = getAccessToken()
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

export function JWTAuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const router = useRouter()

  // Verify current token and get user info
  const verifyAuth = useCallback(async () => {
    const token = getAccessToken()
    if (!token) {
      setLoading(false)
      return
    }

    try {
      const response = await authApi.get('/auth/verify')
      setUser(response.data)
      setError(null)
    } catch (err) {
      console.error('Auth verification failed:', err)
      clearTokens()
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  // Refresh the access token
  const refreshToken = useCallback(async () => {
    const refresh = getRefreshToken()
    if (!refresh) {
      throw new Error('No refresh token available')
    }

    try {
      const response = await authApi.post('/auth/refresh', {
        refresh_token: refresh
      })
      
      const { access_token, refresh_token: newRefreshToken, user } = response.data
      setTokens(access_token, newRefreshToken)
      setUser(user)
      return access_token
    } catch (err) {
      console.error('Token refresh failed:', err)
      clearTokens()
      setUser(null)
      router.push('/simple-login')
      throw err
    }
  }, [router])

  // Setup response interceptor for token refresh
  useEffect(() => {
    const responseInterceptor = authApi.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config
        
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true
          
          try {
            const newToken = await refreshToken()
            originalRequest.headers.Authorization = `Bearer ${newToken}`
            return authApi(originalRequest)
          } catch (refreshError) {
            // Refresh failed, redirect to login
            return Promise.reject(refreshError)
          }
        }
        
        return Promise.reject(error)
      }
    )

    return () => {
      authApi.interceptors.response.eject(responseInterceptor)
    }
  }, [refreshToken])

  // Login function
  const login = async (email: string, password: string) => {
    setLoading(true)
    setError(null)
    
    try {
      const response = await authApi.post('/auth/login', {
        email,
        password
      })
      
      const { access_token, refresh_token, user } = response.data
      setTokens(access_token, refresh_token)
      setUser(user)
      
      // Redirect to dashboard
      router.push('/qa-dashboard')
    } catch (err: any) {
      const errorMessage = err.response?.data?.detail || 'Login failed'
      setError(errorMessage)
      throw new Error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  // Register function
  const register = async (email: string, password: string, name: string) => {
    setLoading(true)
    setError(null)
    
    try {
      const response = await authApi.post('/auth/register', {
        email,
        password,
        name
      })
      
      const { access_token, refresh_token, user } = response.data
      setTokens(access_token, refresh_token)
      setUser(user)
      
      // Redirect to dashboard
      router.push('/qa-dashboard')
    } catch (err: any) {
      const errorMessage = err.response?.data?.detail || 'Registration failed'
      setError(errorMessage)
      throw new Error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  // Logout function
  const logout = async () => {
    setLoading(true)
    
    try {
      const refresh = getRefreshToken()
      
      // Call logout endpoint if we have tokens
      if (getAccessToken()) {
        await authApi.post('/auth/logout', {
          refresh_token: refresh
        })
      }
    } catch (err) {
      console.error('Logout error:', err)
    } finally {
      // Clear local state regardless
      clearTokens()
      setUser(null)
      setError(null)
      setLoading(false)
      router.push('/simple-login')
    }
  }

  // Check authentication on mount
  useEffect(() => {
    verifyAuth()
  }, [verifyAuth])

  // Set up token refresh interval (refresh every 25 minutes)
  useEffect(() => {
    if (!user) return

    const interval = setInterval(() => {
      refreshToken().catch(console.error)
    }, 25 * 60 * 1000) // 25 minutes

    return () => clearInterval(interval)
  }, [user, refreshToken])

  const value: AuthContextType = {
    user,
    loading,
    error,
    login,
    register,
    logout,
    refreshToken,
    isAuthenticated: !!user
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within a JWTAuthProvider')
  }
  return context
}

// Export auth API for use in other services
export { authApi, getAccessToken, getRefreshToken, clearTokens }
