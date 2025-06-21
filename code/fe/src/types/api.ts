/**
 * Authentication API Types
 * 
 * Type definitions for the authentication service API based on OpenAPI specification.
 * These types ensure type safety when communicating with the Go auth service.
 */

/**
 * Standard error response format returned by the API
 */
export interface ErrorResponse {
  /** Brief error code or type */
  error: string
  
  /** Human-readable error description */
  message: string
  
  /** Unique identifier for this request (for debugging) */
  request_id: string
  
  /** When the error occurred */
  timestamp: string
  
  /** Additional error information (validation errors, etc.) */
  details?: unknown
}

/**
 * User information as stored in the database
 */
export interface User {
  /** User's unique identifier */
  id: string
  
  /** User's email address */
  email: string
  
  /** User's given name */
  first_name: string
  
  /** User's family name */
  last_name: string
  
  /** Whether the user account is active */
  is_active: boolean
  
  /** Whether the user has verified their email */
  is_email_verified: boolean
  
  /** When the user account was created */
  created_at: string
  
  /** When the user account was last modified */
  updated_at: string
  
  /** Timestamp of the user's last login */
  last_login_at?: string
  
  /** When the user last changed their password */
  password_changed_at?: string
  
  /** Soft delete timestamp */
  deleted_at?: string
}

/**
 * User information in API responses (excludes sensitive fields)
 */
export interface UserResponse {
  /** User's unique identifier */
  id: string
  
  /** User's email address */
  email: string
  
  /** User's given name */
  first_name: string
  
  /** User's family name */
  last_name: string
  
  /** Computed field combining first and last names */
  full_name: string
  
  /** Whether the user account is active */
  is_active: boolean
  
  /** Whether the user has verified their email */
  is_email_verified: boolean
  
  /** When the user account was created */
  created_at: string
  
  /** When the user account was last modified */
  updated_at: string
  
  /** Timestamp of the user's last login */
  last_login_at?: string
}

/**
 * User registration request payload
 */
export interface RegisterRequest {
  /** User's email address, must be unique in the system */
  email: string
  
  /** User's given name (1-100 characters) */
  first_name: string
  
  /** User's family name (1-100 characters) */
  last_name: string
  
  /** Plain text password (8-128 characters, will be hashed) */
  password: string
  
  /** Password confirmation (must match password) */
  password_confirm: string
}

/**
 * User registration success response
 */
export interface RegisterResponse {
  /** Whether the operation was successful */
  success: boolean
  
  /** Human-readable success message */
  message: string
  
  /** Newly registered user's information */
  user: UserResponse
  
  /** Unique identifier for this request */
  request_id: string
  
  /** When the registration was completed */
  timestamp: string
}

/**
 * User login request payload
 */
export interface LoginRequest {
  /** User's registered email address */
  email: string
  
  /** User's plain text password for verification */
  password: string
  
  /** Whether to extend session duration */
  remember_me?: boolean
}

/**
 * User login success response with JWT tokens
 */
export interface LoginResponse {
  /** JWT token for API authentication */
  access_token: string
  
  /** Token used to obtain new access tokens */
  refresh_token: string
  
  /** Type of token (typically "Bearer") */
  token_type: string
  
  /** Access token lifetime in seconds */
  expires_in: number
  
  /** Authenticated user's information */
  user: UserResponse
  
  /** Unique identifier for this request */
  request_id: string
  
  /** When the login was completed */
  timestamp: string
}

/**
 * Refresh token request payload
 */
export interface RefreshTokenRequest {
  /** JWT refresh token issued during login */
  refresh_token: string
}

/**
 * User profile update request payload
 */
export interface UpdateProfileRequest {
  /** New email address (optional) */
  email?: string
  
  /** New first name (optional) */
  first_name?: string
  
  /** New last name (optional) */
  last_name?: string
}

/**
 * Standard success response for operations without specific data
 */
export interface SuccessResponse {
  /** Whether the operation completed successfully */
  success: boolean
  
  /** Additional context about the operation */
  message: string
  
  /** Unique identifier for this request */
  request_id: string
  
  /** When the operation completed */
  timestamp: string
}

/**
 * Health check information for a single dependency
 */
export interface HealthCheck {
  /** This dependency's health status */
  status: string
  
  /** How long this check took (in milliseconds) */
  response_time_ms: number
  
  /** When this dependency was last checked */
  last_checked: string
  
  /** Error details if the check failed */
  error?: string
}

/**
 * Comprehensive health check response
 */
export interface HealthCheckResponse {
  /** Overall service health ("healthy", "unhealthy", "degraded") */
  status: string
  
  /** Service version */
  version: string
  
  /** When the health check was performed */
  timestamp: string
  
  /** Detailed health information for dependencies */
  checks: Record<string, HealthCheck>
}

/**
 * JWT token payload interface
 */
export interface JWTPayload {
  /** Subject (user ID) */
  sub: string
  
  /** User email */
  email: string
  
  /** Token type ("access" or "refresh") */
  token_type: string
  
  /** Issued at timestamp */
  iat: number
  
  /** Expiration timestamp */
  exp: number
  
  /** Issuer */
  iss: string
  
  /** Audience */
  aud: string
}

/**
 * Application theme modes
 */
export type ThemeMode = 'light' | 'dark' | 'system'

/**
 * Navigation route information
 */
export interface NavigationRoute {
  /** Route name/identifier */
  name: string
  
  /** Display title */
  title: string
  
  /** Route path */
  path: string
  
  /** Material Design Icon name */
  icon: string
  
  /** Whether authentication is required */
  requiresAuth: boolean
  
  /** Whether to show in navigation menu */
  showInMenu: boolean
  
  /** Route order in menu */
  order?: number
}

/**
 * API response wrapper for consistent error handling
 */
export type ApiResponse<T> = {
  success: true
  data: T
} | {
  success: false
  error: ErrorResponse
}

/**
 * Request to initiate password reset process
 */
export interface ForgotPasswordRequest {
  /** Email address of the user requesting password reset */
  email: string
}

/**
 * Request to complete password reset with token
 */
export interface ResetPasswordRequest {
  /** Password reset token received via email */
  token: string
  /** New password to set for the user account */
  new_password: string
}
