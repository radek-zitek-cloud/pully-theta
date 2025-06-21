/**
 * Application State Types
 * 
 * Type definitions for Pinia stores and application state management.
 * These types ensure consistency across all store implementations.
 */

import type { UserResponse, ThemeMode } from './api'

/**
 * Authentication state interface
 */
export interface AuthState {
  /** Current authenticated user */
  user: UserResponse | null
  
  /** JWT access token */
  accessToken: string | null
  
  /** JWT refresh token */
  refreshToken: string | null
  
  /** Token expiration timestamp */
  tokenExpiresAt: number | null
  
  /** Whether user is currently authenticated */
  isAuthenticated: boolean
  
  /** Whether authentication is being checked */
  isLoading: boolean
  
  /** Remember me preference */
  rememberMe: boolean
  
  /** Last login timestamp */
  lastLogin: string | null
}

/**
 * Application UI state interface
 */
export interface UIState {
  /** Current theme mode */
  theme: ThemeMode
  
  /** Whether sidebar is open */
  sidebarOpen: boolean
  
  /** Whether app is in mobile view */
  isMobile: boolean
  
  /** Current page loading state */
  isPageLoading: boolean
  
  /** Global loading overlay state */
  isGlobalLoading: boolean
  
  /** Snackbar notifications */
  notifications: NotificationState[]
  
  /** Confirmation dialog state */
  confirmDialog: ConfirmDialogState | null
}

/**
 * Notification state for snackbar messages
 */
export interface NotificationState {
  /** Unique notification ID */
  id: string
  
  /** Notification message */
  message: string
  
  /** Notification type/severity */
  type: 'success' | 'error' | 'warning' | 'info'
  
  /** Auto-hide timeout in milliseconds */
  timeout?: number
  
  /** Whether notification can be dismissed */
  dismissible: boolean
  
  /** Additional actions for the notification */
  actions?: NotificationAction[]
  
  /** Timestamp when notification was created */
  createdAt: number
}

/**
 * Notification action interface
 */
export interface NotificationAction {
  /** Action label */
  label: string
  
  /** Action handler function */
  handler: () => void
  
  /** Action color */
  color?: string
}

/**
 * Confirmation dialog state
 */
export interface ConfirmDialogState {
  /** Whether dialog is visible */
  visible: boolean
  
  /** Dialog title */
  title: string
  
  /** Dialog message/content */
  message: string
  
  /** Confirm button text */
  confirmText: string
  
  /** Cancel button text */
  cancelText: string
  
  /** Confirm button color */
  confirmColor: string
  
  /** Whether the action is destructive */
  destructive: boolean
  
  /** Callback for confirm action */
  onConfirm: () => void | Promise<void>
  
  /** Callback for cancel action */
  onCancel?: () => void
}

/**
 * Form validation state
 */
export interface FormState<T = Record<string, unknown>> {
  /** Form data */
  data: T
  
  /** Form validation errors */
  errors: Record<keyof T, string[]>
  
  /** Whether form is currently submitting */
  isSubmitting: boolean
  
  /** Whether form has been submitted */
  hasSubmitted: boolean
  
  /** Whether form is valid */
  isValid: boolean
  
  /** Form touched fields */
  touched: Record<keyof T, boolean>
}

/**
 * Data table state for list views
 */
export interface DataTableState<T = unknown> {
  /** Table items */
  items: T[]
  
  /** Total number of items */
  total: number
  
  /** Current page number */
  page: number
  
  /** Items per page */
  itemsPerPage: number
  
  /** Sort by field */
  sortBy: string[]
  
  /** Sort order */
  sortDesc: boolean[]
  
  /** Search query */
  search: string
  
  /** Whether data is loading */
  loading: boolean
  
  /** Selected items */
  selectedItems: T[]
  
  /** Table filters */
  filters: Record<string, unknown>
}

/**
 * Async operation state
 */
export interface AsyncState<T = unknown> {
  /** Operation data */
  data: T | null
  
  /** Whether operation is loading */
  loading: boolean
  
  /** Operation error */
  error: string | null
  
  /** Last update timestamp */
  lastUpdated: number | null
  
  /** Whether operation was successful */
  success: boolean
}

/**
 * Pagination state
 */
export interface PaginationState {
  /** Current page number (1-based) */
  page: number
  
  /** Items per page */
  limit: number
  
  /** Total number of items */
  total: number
  
  /** Total number of pages */
  totalPages: number
  
  /** Whether there is a next page */
  hasNext: boolean
  
  /** Whether there is a previous page */
  hasPrev: boolean
}

/**
 * Search and filter state
 */
export interface SearchState {
  /** Search query string */
  query: string
  
  /** Active filters */
  filters: Record<string, unknown>
  
  /** Sort configuration */
  sort: {
    field: string
    direction: 'asc' | 'desc'
  }
  
  /** Date range filter */
  dateRange?: {
    start: string
    end: string
  }
}

/**
 * Application settings state
 */
export interface SettingsState {
  /** User preferences */
  preferences: {
    /** Theme mode */
    theme: ThemeMode
    
    /** Language/locale */
    locale: string
    
    /** Timezone */
    timezone: string
    
    /** Date format preference */
    dateFormat: string
    
    /** Time format preference */
    timeFormat: '12h' | '24h'
    
    /** Notifications enabled */
    notificationsEnabled: boolean
    
    /** Email notifications enabled */
    emailNotificationsEnabled: boolean
  }
  
  /** Application configuration */
  config: {
    /** API base URL */
    apiBaseUrl: string
    
    /** Application version */
    version: string
    
    /** Debug mode */
    debugMode: boolean
    
    /** Feature flags */
    features: Record<string, boolean>
  }
}

/**
 * Route meta information
 */
export interface RouteMeta {
  /** Page title */
  title?: string
  
  /** Whether authentication is required */
  requiresAuth?: boolean
  
  /** Required user roles */
  roles?: string[]
  
  /** Whether to show in breadcrumbs */
  showInBreadcrumbs?: boolean
  
  /** Page icon */
  icon?: string
  
  /** Layout to use */
  layout?: string
  
  /** Whether to keep component alive */
  keepAlive?: boolean
  
  /** Index signature to satisfy vue-router's RouteMeta constraint */
  [key: PropertyKey]: unknown
}
