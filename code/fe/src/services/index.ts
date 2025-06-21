/**
 * API Services Barrel Export
 * 
 * Centralized export for all API service modules.
 * Provides convenient imports for service classes throughout the application.
 */

export { default as httpClient } from './http-client'
export { default as authService } from './auth.service'

// Re-export service instances for convenient access
export { httpClient as http } from './http-client'
export { authService as auth } from './auth.service'
