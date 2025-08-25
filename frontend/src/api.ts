// JWT-based API client (replaces Firebase-dependent api.ts)

import { clearTokens, getAccessToken } from '@/contexts/JWTAuthContext'
import axios, { AxiosError, AxiosInstance } from 'axios'

// Create base API instance
const baseURL = process.env.NEXT_PUBLIC_API_URL || '/api/v1'

const api: AxiosInstance = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Send cookies with requests
})

// Request interceptor to add auth token
api.interceptors.request.use(
  async (config) => {
    // Skip auth for public endpoints
    const publicEndpoints = ['/auth/login', '/auth/register', '/health']
    const isPublicEndpoint = publicEndpoints.some(endpoint => 
      config.url?.includes(endpoint)
    )
    
    if (!isPublicEndpoint) {
      // Get token from localStorage or cookie
      const token = getAccessToken()
      
      if (token) {
        config.headers.Authorization = `Bearer ${token}`
      }
    }
    
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    // Handle 401 errors (unauthorized)
    if (error.response?.status === 401) {
      const originalRequest = error.config as any
      
      // Prevent infinite loop
      if (!originalRequest._retry) {
        originalRequest._retry = true
        
        // Try to refresh the token
        try {
          const refreshToken = localStorage.getItem('refresh_token')
          if (refreshToken) {
            const response = await api.post('/auth/refresh', {
              refresh_token: refreshToken
            })
            
            const { access_token, refresh_token } = response.data
            localStorage.setItem('auth_token', access_token)
            localStorage.setItem('refresh_token', refresh_token)
            
            // Retry original request with new token
            originalRequest.headers.Authorization = `Bearer ${access_token}`
            return api(originalRequest)
          }
        } catch (refreshError) {
          // Refresh failed, clear tokens and redirect to login
          clearTokens()
          if (typeof window !== 'undefined' && !window.location.pathname.includes('/login')) {
            window.location.href = '/login'
          }
        }
      }
    }
    
    return Promise.reject(error)
  }
)

// API service methods
export const authAPI = {
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }),
  
  register: (email: string, password: string, name: string) =>
    api.post('/auth/register', { email, password, name }),
  
  logout: (refreshToken?: string) =>
    api.post('/auth/logout', { refresh_token: refreshToken }),
  
  verify: () =>
    api.get('/auth/verify'),
  
  refreshTokens: (refreshToken: string) =>
    api.post('/auth/refresh', { refresh_token: refreshToken }),
  
  updatePassword: (currentPassword: string, newPassword: string) =>
    api.put('/auth/password', {
      current_password: currentPassword,
      new_password: newPassword
    }),
  
  requestPasswordReset: (email: string) =>
    api.post('/auth/password-reset', { email }),
  
  confirmPasswordReset: (token: string, newPassword: string) =>
    api.post('/auth/password-reset/confirm', {
      token,
      new_password: newPassword
    }),
}

// QA Dashboard API
export const qaAPI = {
  getCalls: (params?: any) =>
    api.get('/qa/calls', { params }),
  
  getCallById: (id: string) =>
    api.get(`/qa/calls/${id}`),
  
  getCallAudioUrl: (id: string) =>
    api.get(`/qa/calls/${id}/audio-url`),
  
  getDashboardData: () =>
    api.get('/qa-dashboard/data'),
  
  getRealtimeMetrics: () =>
    api.get('/realtime/metrics'),
  
  searchCalls: (query: string) =>
    api.get('/qa/search', { params: { q: query } }),
}

// Recordings API
export const recordingsAPI = {
  list: (params?: any) =>
    api.get('/recordings', { params }),
  
  get: (id: string) =>
    api.get(`/recordings/${id}`),
  
  delete: (id: string) =>
    api.delete(`/recordings/${id}`),
  
  getAudioUrl: (id: string) =>
    api.get(`/recordings/${id}/audio-url`),
}

// Admin API
export const adminAPI = {
  getUsers: () =>
    api.get('/admin/users'),
  
  getSystemHealth: () =>
    api.get('/admin/health'),
  
  getCredentials: () =>
    api.get('/admin/credentials'),
  
  updateCredentials: (credentials: any) =>
    api.put('/admin/credentials', credentials),
  
  // TLD Integration
  setupTLDIntegration: (data: {
    subdomain: string
    auth_method: string
    api_id?: string
    api_key?: string
  }) => api.post('/integrations/tld-crm/credentials', data),
  
  testTLDConnection: () =>
    api.post('/integrations/tld-crm/test'),
}

// User Preferences API
export const preferencesAPI = {
  get: () =>
    api.get('/auth/preferences'),
  
  update: (preferences: any) =>
    api.post('/auth/preferences', preferences),
  
  updateTimezone: (timezone: string, travelMode?: boolean) =>
    api.put('/auth/preferences/timezone', { timezone, travel_mode: travelMode }),
}

// Export the base API instance for custom usage
export default api

// Export the main API object and specific APIs for backward compatibility
export { api }
