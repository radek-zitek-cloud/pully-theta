/**
 * UI Store
 * 
 * Pinia store for managing application UI state including theme,
 * sidebar navigation, notifications, dialogs, and loading states.
 */

import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { 
  ThemeMode, 
  NotificationState, 
  ConfirmDialogState,
  NotificationAction
} from '@/types'

/**
 * UI store using Composition API syntax
 * 
 * Features:
 * - Theme management (light/dark/system)
 * - Sidebar navigation state
 * - Responsive design utilities
 * - Global loading states
 * - Notification system (snackbars)
 * - Confirmation dialogs
 * - Persistent UI preferences
 */
export const useUIStore = defineStore('ui', () => {
  // State
  const theme = ref<ThemeMode>('system')
  const sidebarOpen = ref(false)
  const isMobile = ref(false)
  const isPageLoading = ref(false)
  const isGlobalLoading = ref(false)
  const notifications = ref<NotificationState[]>([])
  const confirmDialog = ref<ConfirmDialogState | null>(null)

  // Getters
  const activeTheme = computed(() => {
    if (theme.value === 'system') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
    }
    return theme.value
  })

  const hasNotifications = computed(() => notifications.value.length > 0)

  const sidebarWidth = computed(() => {
    if (isMobile.value) return '100vw'
    return sidebarOpen.value ? '280px' : '64px'
  })

  // Actions

  /**
   * Set the application theme
   * 
   * @param newTheme - Theme mode to set
   */
  function setTheme(newTheme: ThemeMode) {
    theme.value = newTheme
    applyTheme()
  }

  /**
   * Toggle between light and dark themes
   */
  function toggleTheme() {
    const currentTheme = activeTheme.value
    setTheme(currentTheme === 'light' ? 'dark' : 'light')
  }

  /**
   * Apply the current theme to the document
   */
  function applyTheme() {
    const htmlElement = document.documentElement
    const currentTheme = activeTheme.value
    
    htmlElement.setAttribute('data-theme', currentTheme)
    htmlElement.classList.remove('light-theme', 'dark-theme')
    htmlElement.classList.add(`${currentTheme}-theme`)
  }

  /**
   * Toggle sidebar open/closed state
   */
  function toggleSidebar() {
    sidebarOpen.value = !sidebarOpen.value
  }

  /**
   * Set sidebar open state
   * 
   * @param open - Whether sidebar should be open
   */
  function setSidebarOpen(open: boolean) {
    sidebarOpen.value = open
  }

  /**
   * Set mobile view state
   * 
   * @param mobile - Whether app is in mobile view
   */
  function setMobile(mobile: boolean) {
    isMobile.value = mobile
    
    // Auto-close sidebar on mobile when switching to desktop
    if (!mobile && sidebarOpen.value) {
      sidebarOpen.value = false
    }
  }

  /**
   * Set page loading state
   * 
   * @param loading - Whether page is loading
   */
  function setPageLoading(loading: boolean) {
    isPageLoading.value = loading
  }

  /**
   * Set global loading state
   * 
   * @param loading - Whether global loading overlay should be shown
   */
  function setGlobalLoading(loading: boolean) {
    isGlobalLoading.value = loading
  }

  /**
   * Show a notification snackbar
   * 
   * @param message - Notification message
   * @param type - Notification type/severity
   * @param options - Additional notification options
   */
  function showNotification(
    message: string,
    type: NotificationState['type'] = 'info',
    options: {
      timeout?: number
      dismissible?: boolean
      actions?: NotificationAction[]
    } = {}
  ) {
    const notification: NotificationState = {
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      message,
      type,
      timeout: options.timeout ?? (type === 'error' ? 0 : 5000), // Errors stay until dismissed
      dismissible: options.dismissible ?? true,
      actions: options.actions ?? [],
      createdAt: Date.now()
    }

    notifications.value.push(notification)

    // Auto-remove notification if timeout is set
    if (notification.timeout && notification.timeout > 0) {
      setTimeout(() => {
        dismissNotification(notification.id)
      }, notification.timeout)
    }

    return notification.id
  }

  /**
   * Show success notification
   * 
   * @param message - Success message
   * @param options - Additional options
   */
  function showSuccess(message: string, options?: { timeout?: number; actions?: NotificationAction[] }) {
    return showNotification(message, 'success', options)
  }

  /**
   * Show error notification
   * 
   * @param message - Error message
   * @param options - Additional options
   */
  function showError(message: string, options?: { timeout?: number; actions?: NotificationAction[] }) {
    return showNotification(message, 'error', { timeout: 0, ...options })
  }

  /**
   * Show warning notification
   * 
   * @param message - Warning message
   * @param options - Additional options
   */
  function showWarning(message: string, options?: { timeout?: number; actions?: NotificationAction[] }) {
    return showNotification(message, 'warning', options)
  }

  /**
   * Show info notification
   * 
   * @param message - Info message
   * @param options - Additional options
   */
  function showInfo(message: string, options?: { timeout?: number; actions?: NotificationAction[] }) {
    return showNotification(message, 'info', options)
  }

  /**
   * Dismiss a specific notification
   * 
   * @param notificationId - ID of notification to dismiss
   */
  function dismissNotification(notificationId: string) {
    const index = notifications.value.findIndex(n => n.id === notificationId)
    if (index > -1) {
      notifications.value.splice(index, 1)
    }
  }

  /**
   * Clear all notifications
   */
  function clearNotifications() {
    notifications.value = []
  }

  /**
   * Show a confirmation dialog
   * 
   * @param options - Dialog configuration
   * @returns Promise resolving to user's choice
   */
  function showConfirmDialog(options: {
    title: string
    message: string
    confirmText?: string
    cancelText?: string
    confirmColor?: string
    destructive?: boolean
  }): Promise<boolean> {
    return new Promise((resolve) => {
      confirmDialog.value = {
        visible: true,
        title: options.title,
        message: options.message,
        confirmText: options.confirmText || 'Confirm',
        cancelText: options.cancelText || 'Cancel',
        confirmColor: options.confirmColor || (options.destructive ? 'error' : 'primary'),
        destructive: options.destructive || false,
        onConfirm: () => {
          confirmDialog.value = null
          resolve(true)
        },
        onCancel: () => {
          confirmDialog.value = null
          resolve(false)
        }
      }
    })
  }

  /**
   * Hide the confirmation dialog
   */
  function hideConfirmDialog() {
    confirmDialog.value = null
  }

  /**
   * Initialize UI store (called on app startup)
   */
  function initialize() {
    // Apply saved theme
    applyTheme()
    
    // Listen for system theme changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    mediaQuery.addEventListener('change', () => {
      if (theme.value === 'system') {
        applyTheme()
      }
    })

    // Setup responsive breakpoint detection
    const mobileMediaQuery = window.matchMedia('(max-width: 960px)')
    setMobile(mobileMediaQuery.matches)
    mobileMediaQuery.addEventListener('change', (e) => {
      setMobile(e.matches)
    })
  }

  return {
    // State
    theme,
    sidebarOpen,
    isMobile,
    isPageLoading,
    isGlobalLoading,
    notifications,
    confirmDialog,
    
    // Getters
    activeTheme,
    hasNotifications,
    sidebarWidth,
    
    // Actions
    setTheme,
    toggleTheme,
    applyTheme,
    toggleSidebar,
    setSidebarOpen,
    setMobile,
    setPageLoading,
    setGlobalLoading,
    showNotification,
    showSuccess,
    showError,
    showWarning,
    showInfo,
    dismissNotification,
    clearNotifications,
    showConfirmDialog,
    hideConfirmDialog,
    initialize
  }
}, {
  persist: {
    key: 'ui-store',
    storage: localStorage,
    paths: ['theme', 'sidebarOpen']
  }
})
