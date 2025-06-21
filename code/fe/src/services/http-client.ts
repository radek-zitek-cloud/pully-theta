/**
 * HTTP Client Configuration
 * 
 * Configured Axios instance for API communication with the Go auth service.
 * Includes request/response interceptors for authentication, error handling,
 * and consistent response formatting.
 */

import axios, { 
  type AxiosInstance, 
  type AxiosRequestConfig, 
  type AxiosResponse, 
  type InternalAxiosRequestConfig 
} from 'axios'
import type { ErrorResponse } from '@/types'

/**
 * HTTP client class for API communication
 * 
 * Features:
 * - Automatic JWT token injection
 * - Response/error interceptors
 * - Request/response logging in development
 * - Consistent error handling
 * - Token refresh logic
 * 
 * Time Complexity: O(1) for all operations
 * Space Complexity: O(1)
 */
class HttpClient {
  private client: AxiosInstance
  private isRefreshing = false
  private failedQueue: Array<{
    resolve: (value?: unknown) => void
    reject: (reason?: unknown) => void
  }> = []

  constructor() {
    // Create axios instance with base configuration
    this.client = axios.create({
      baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:6910/api/v1',
      timeout: 30000, // 30 second timeout
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    })

    this.setupInterceptors()
  }

  /**
   * Setup request and response interceptors
   * 
   * Request interceptor:
   * - Adds JWT token to Authorization header
   * - Logs requests in development mode
   * 
   * Response interceptor:
   * - Handles successful responses
   * - Processes error responses consistently
   * - Implements token refresh logic
   */
  private setupInterceptors(): void {
    // Request interceptor
    this.client.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        // Add authorization token if available
        const token = this.getStoredToken()
        if (token && config.headers) {
          config.headers.Authorization = `Bearer ${token}`
        }

        // Log request in development
        if (import.meta.env.DEV) {
          console.log(`🚀 API Request: ${config.method?.toUpperCase()} ${config.url}`)
        }

        return config
      },
      error => {
        console.error('❌ Request interceptor error:', error)
        return Promise.reject(error)
      }
    )

    // Response interceptor
    this.client.interceptors.response.use(
      (response: AxiosResponse) => {
        // Log successful response in development
        if (import.meta.env.DEV) {
          console.log(`✅ API Response: ${response.status} ${response.config.url}`)
        }
        return response
      },
      async error => {
        const originalRequest = error.config

        // Handle 401 unauthorized errors with token refresh
        if (error.response?.status === 401 && !originalRequest._retry) {
          if (this.isRefreshing) {
            // Queue the request while refresh is in progress
            return new Promise((resolve, reject) => {
              this.failedQueue.push({ resolve, reject })
            }).then(token => {
              originalRequest.headers.Authorization = `Bearer ${token}`
              return this.client(originalRequest)
            }).catch(err => {
              return Promise.reject(err)
            })
          }

          originalRequest._retry = true
          this.isRefreshing = true

          try {
            const newToken = await this.refreshToken()
            this.processQueue(null, newToken)
            originalRequest.headers.Authorization = `Bearer ${newToken}`
            return this.client(originalRequest)
          } catch (refreshError) {
            this.processQueue(refreshError, null)
            this.clearTokens()
            // Redirect to login page or emit auth error event
            window.dispatchEvent(new CustomEvent('auth:token-expired'))
            return Promise.reject(refreshError)
          } finally {
            this.isRefreshing = false
          }
        }

        // Log error in development
        if (import.meta.env.DEV) {
          console.error(`❌ API Error: ${error.response?.status} ${error.config?.url}`, error.response?.data)
        }

        // Transform error response to consistent format
        const errorResponse: ErrorResponse = {
          error: error.response?.data?.error || 'unknown_error',
          message: error.response?.data?.message || error.message || 'An unexpected error occurred',
          request_id: error.response?.data?.request_id || '',
          timestamp: error.response?.data?.timestamp || new Date().toISOString(),
          details: error.response?.data?.details
        }

        return Promise.reject(errorResponse)
      }
    )
  }

  /**
   * Process the queue of failed requests after token refresh
   * 
   * @param error - Error from token refresh (if any)
   * @param token - New access token (if refresh successful)
   */
  private processQueue(error: unknown, token: string | null): void {
    this.failedQueue.forEach(({ resolve, reject }) => {
      if (error) {
        reject(error)
      } else {
        resolve(token)
      }
    })
    
    this.failedQueue = []
  }

  /**
   * Refresh JWT access token using stored refresh token
   * 
   * @returns Promise resolving to new access token
   * @throws Error if refresh fails
   */
  private async refreshToken(): Promise<string> {
    const refreshToken = this.getStoredRefreshToken()
    if (!refreshToken) {
      throw new Error('No refresh token available')
    }

    try {
      const response = await axios.post(
        `${import.meta.env.VITE_API_BASE_URL}/auth/refresh`,
        { refresh_token: refreshToken },
        { timeout: 10000 }
      )

      const { access_token, refresh_token: newRefreshToken } = response.data
      this.storeTokens(access_token, newRefreshToken)
      
      return access_token
    } catch (error) {
      this.clearTokens()
      throw error
    }
  }

  /**
   * Get stored access token from localStorage
   * 
   * @returns Access token or null if not found
   */
  private getStoredToken(): string | null {
    return localStorage.getItem('access_token')
  }

  /**
   * Get stored refresh token from localStorage
   * 
   * @returns Refresh token or null if not found
   */
  private getStoredRefreshToken(): string | null {
    return localStorage.getItem('refresh_token')
  }

  /**
   * Store JWT tokens in localStorage
   * 
   * @param accessToken - JWT access token
   * @param refreshToken - JWT refresh token
   */
  private storeTokens(accessToken: string, refreshToken: string): void {
    localStorage.setItem('access_token', accessToken)
    localStorage.setItem('refresh_token', refreshToken)
  }

  /**
   * Clear stored tokens from localStorage
   */
  private clearTokens(): void {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
  }

  /**
   * Make GET request
   * 
   * @param url - Request URL
   * @param config - Optional axios configuration
   * @returns Promise resolving to response data
   */
  async get<T = unknown>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.get<T>(url, config)
    return response.data
  }

  /**
   * Make POST request
   * 
   * @param url - Request URL
   * @param data - Request payload
   * @param config - Optional axios configuration
   * @returns Promise resolving to response data
   */
  async post<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.post<T>(url, data, config)
    return response.data
  }

  /**
   * Make PUT request
   * 
   * @param url - Request URL
   * @param data - Request payload
   * @param config - Optional axios configuration
   * @returns Promise resolving to response data
   */
  async put<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.put<T>(url, data, config)
    return response.data
  }

  /**
   * Make PATCH request
   * 
   * @param url - Request URL
   * @param data - Request payload
   * @param config - Optional axios configuration
   * @returns Promise resolving to response data
   */
  async patch<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.patch<T>(url, data, config)
    return response.data
  }

  /**
   * Make DELETE request
   * 
   * @param url - Request URL
   * @param config - Optional axios configuration
   * @returns Promise resolving to response data
   */
  async delete<T = unknown>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.delete<T>(url, config)
    return response.data
  }

  /**
   * Set authorization token for subsequent requests
   * 
   * @param token - JWT access token
   */
  setAuthToken(token: string): void {
    this.client.defaults.headers.common['Authorization'] = `Bearer ${token}`
  }

  /**
   * Clear authorization token
   */
  clearAuthToken(): void {
    delete this.client.defaults.headers.common['Authorization']
  }

  /**
   * Get the underlying axios instance for advanced usage
   * 
   * @returns Axios instance
   */
  getInstance(): AxiosInstance {
    return this.client
  }
}

// Export singleton instance
export const httpClient = new HttpClient()
export default httpClient
