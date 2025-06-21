/**
 * Authentication Service
 * 
 * Service class for handling all authentication-related API calls.
 * Provides methods for login, register, logout, token refresh, and profile management.
 * Implements proper error handling and token management.
 */

import httpClient from './http-client'
import type {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  RefreshTokenRequest,
  UpdateProfileRequest,
  UserResponse,
  SuccessResponse,
  ForgotPasswordRequest,
  ResetPasswordRequest
} from '@/types'

/**
 * Authentication service class
 * 
 * Handles all authentication operations including:
 * - User registration and login
 * - JWT token management
 * - User profile operations
 * - Session management
 * 
 * All methods return promises and handle errors consistently.
 * Tokens are automatically managed by the HTTP client.
 */
class AuthService {
  /**
   * Register a new user account
   * 
   * @param data - User registration data
   * @returns Promise resolving to registration response
   * @throws ErrorResponse on validation or server errors
   * 
   * @example
   * ```typescript
   * const response = await authService.register({
   *   email: 'user@example.com',
   *   first_name: 'John',
   *   last_name: 'Doe',
   *   password: 'SecurePass123!',
   *   password_confirm: 'SecurePass123!'
   * })
   * ```
   */
  async register(data: RegisterRequest): Promise<RegisterResponse> {
    return httpClient.post<RegisterResponse>('/auth/register', data)
  }

  /**
   * Authenticate user with email and password
   * 
   * @param data - User login credentials
   * @returns Promise resolving to login response with JWT tokens
   * @throws ErrorResponse on authentication failure
   * 
   * @example
   * ```typescript
   * const response = await authService.login({
   *   email: 'user@example.com',
   *   password: 'SecurePass123!',
   *   remember_me: true
   * })
   * ```
   */
  async login(data: LoginRequest): Promise<LoginResponse> {
    const response = await httpClient.post<LoginResponse>('/auth/login', data)
    
    // Store tokens for subsequent requests
    if (response.access_token && response.refresh_token) {
      this.storeTokens(response.access_token, response.refresh_token)
      httpClient.setAuthToken(response.access_token)
    }
    
    return response
  }

  /**
   * Refresh access token using refresh token
   * 
   * @param data - Refresh token request data
   * @returns Promise resolving to new login response
   * @throws ErrorResponse if refresh token is invalid
   * 
   * @example
   * ```typescript
   * const response = await authService.refreshToken({
   *   refresh_token: 'stored_refresh_token'
   * })
   * ```
   */
  async refreshToken(data: RefreshTokenRequest): Promise<LoginResponse> {
    const response = await httpClient.post<LoginResponse>('/auth/refresh', data)
    
    // Update stored tokens
    if (response.access_token && response.refresh_token) {
      this.storeTokens(response.access_token, response.refresh_token)
      httpClient.setAuthToken(response.access_token)
    }
    
    return response
  }

  /**
   * Logout user and revoke refresh tokens
   * 
   * @returns Promise resolving to success response
   * @throws ErrorResponse on server error
   * 
   * This method requires authentication (Bearer token in header).
   * 
   * @example
   * ```typescript
   * await authService.logout()
   * ```
   */
  async logout(): Promise<SuccessResponse> {
    try {
      const response = await httpClient.post<SuccessResponse>('/auth/logout')
      return response
    } finally {
      // Always clear local tokens, even if server request fails
      this.clearTokens()
      httpClient.clearAuthToken()
    }
  }

  /**
   * Logout from all devices by revoking all refresh tokens
   * 
   * @returns Promise resolving to success response
   * @throws ErrorResponse on server error
   * 
   * This method requires authentication (Bearer token in header).
   * 
   * @example
   * ```typescript
   * await authService.logoutAll()
   * ```
   */
  async logoutAll(): Promise<SuccessResponse> {
    try {
      const response = await httpClient.post<SuccessResponse>('/auth/logout-all')
      return response
    } finally {
      // Always clear local tokens, even if server request fails
      this.clearTokens()
      httpClient.clearAuthToken()
    }
  }

  /**
   * Get current authenticated user's profile
   * 
   * @returns Promise resolving to user profile data
   * @throws ErrorResponse if not authenticated or server error
   * 
   * This method requires authentication (Bearer token in header).
   * 
   * @example
   * ```typescript
   * const user = await authService.getCurrentUser()
   * console.log(user.full_name)
   * ```
   */
  async getCurrentUser(): Promise<UserResponse> {
    return httpClient.get<UserResponse>('/auth/me')
  }

  /**
   * Update authenticated user's profile information
   * 
   * @param data - Profile update data (partial updates supported)
   * @returns Promise resolving to updated user profile
   * @throws ErrorResponse on validation errors or server error
   * 
   * This method requires authentication (Bearer token in header).
   * Supports partial updates - only provided fields will be updated.
   * 
   * @example
   * ```typescript
   * const updatedUser = await authService.updateProfile({
   *   first_name: 'UpdatedName',
   *   email: 'newemail@example.com'
   * })
   * ```
   */
  async updateProfile(data: UpdateProfileRequest): Promise<UserResponse> {
    return httpClient.put<UserResponse>('/auth/me', data)
  }

  /**
   * Change user password
   * 
   * Updates the user's password by verifying the current password
   * and setting a new one. Requires current password verification
   * for security purposes.
   * 
   * @param data - Password change data including current and new passwords
   * @returns Promise resolving when password is successfully changed
   * @throws ErrorResponse on validation errors or if current password is incorrect
   * 
   * @example
   * ```typescript
   * await authService.changePassword({
   *   currentPassword: 'oldpass123',
   *   newPassword: 'NewSecurePass456!',
   *   confirmPassword: 'NewSecurePass456!'
   * })
   * ```
   */
  async changePassword(data: {
    currentPassword: string
    newPassword: string
    confirmPassword: string
  }): Promise<void> {
    return httpClient.put<void>('/auth/change-password', {
      current_password: data.currentPassword,
      new_password: data.newPassword,
      confirm_password: data.confirmPassword
    })
  }

  /**
   * Request password reset via email
   * 
   * Initiates the password reset process by sending a reset token
   * to the user's email address. This is a public endpoint that
   * doesn't require authentication.
   * 
   * @param data - Password reset request data
   * @returns Promise resolving when reset email is sent
   * @throws ErrorResponse on validation or server errors
   * 
   * @example
   * ```typescript
   * await authService.forgotPassword({
   *   email: 'user@example.com'
   * })
   * ```
   * 
   * @security This endpoint always returns success to prevent email enumeration attacks.
   *           The actual reset token is sent only to valid email addresses.
   */
  async forgotPassword(data: ForgotPasswordRequest): Promise<SuccessResponse> {
    return httpClient.post<SuccessResponse>('/password/forgot', {
      email: data.email
    })
  }

  /**
   * Complete password reset with token
   * 
   * Completes the password reset process using the token received
   * via email and sets a new password for the user account.
   * 
   * @param data - Password reset completion data
   * @returns Promise resolving when password is successfully reset
   * @throws ErrorResponse on invalid token or validation errors
   * 
   * @example
   * ```typescript
   * await authService.resetPassword({
   *   token: 'reset-token-from-email',
   *   new_password: 'NewSecurePassword123!'
   * })
   * ```
   */
  async resetPassword(data: ResetPasswordRequest): Promise<SuccessResponse> {
    return httpClient.post<SuccessResponse>('/password/reset', {
      token: data.token,
      new_password: data.new_password
    })
  }

  /**
   * Check if user is currently authenticated
   * 
   * @returns True if access token exists and is not expired
   * 
   * This is a client-side check only. For server-side validation,
   * use getCurrentUser() which will validate the token with the server.
   * 
   * @example
   * ```typescript
   * if (authService.isAuthenticated()) {
   *   // User is logged in
   * }
   * ```
   */
  isAuthenticated(): boolean {
    const token = this.getStoredAccessToken()
    if (!token) return false

    try {
      const payload = this.parseJWT(token)
      const now = Math.floor(Date.now() / 1000)
      return payload.exp > now
    } catch {
      return false
    }
  }

  /**
   * Get stored access token
   * 
   * @returns Access token or null if not found
   */
  getStoredAccessToken(): string | null {
    return localStorage.getItem('access_token')
  }

  /**
   * Get stored refresh token
   * 
   * @returns Refresh token or null if not found
   */
  getStoredRefreshToken(): string | null {
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
    localStorage.setItem('token_stored_at', Date.now().toString())
  }

  /**
   * Clear stored tokens from localStorage
   */
  private clearTokens(): void {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    localStorage.removeItem('token_stored_at')
  }

  /**
   * Parse JWT token to extract payload
   * 
   * @param token - JWT token string
   * @returns Parsed JWT payload
   * @throws Error if token is malformed
   */
  private parseJWT(token: string): { exp: number; [key: string]: unknown } {
    try {
      const base64Url = token.split('.')[1]
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split('')
          .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      )
      return JSON.parse(jsonPayload)
    } catch (error) {
      throw new Error('Invalid JWT token format')
    }
  }
}

// Export singleton instance
export const authService = new AuthService()
export default authService
