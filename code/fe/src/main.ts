/**
 * Application Entry Point
 * 
 * Main Vue.js application setup with all plugins, stores, and global configuration.
 * Initializes Vuetify, Pinia, Vue Router, and other essential services.
 */

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import piniaPluginPersistedstate from 'pinia-plugin-persistedstate'

// Import main App component
import App from './App.vue'

// Import plugins and configuration
import router from './router'
import vuetify from './plugins/vuetify'

// Import stores for initialization
import { useAuthStore } from '@/stores/auth.store'
import { useUIStore } from '@/stores/ui.store'

// Import global styles
import './styles/main.css'

/**
 * Create and configure the Vue application instance
 * 
 * This function sets up the entire application with all necessary plugins,
 * stores, and configurations. It also handles the initial app state setup.
 */
async function createVueApp() {
  // Create Vue app instance
  const app = createApp(App)
  
  // Create and configure Pinia store
  const pinia = createPinia()
  pinia.use(piniaPluginPersistedstate)
  
  // Install plugins
  app.use(pinia)
  app.use(router)
  app.use(vuetify)
  
  // Global error handler
  app.config.errorHandler = (error, instance, info) => {
    console.error('Global Vue error:', error)
    console.error('Component instance:', instance)
    console.error('Error info:', info)
    
    // Show user-friendly error message
    const uiStore = useUIStore()
    uiStore.showError('An unexpected error occurred. Please refresh the page.')
  }
  
  // Global warning handler (development only)
  if (import.meta.env.DEV) {
    app.config.warnHandler = (msg, _instance, trace) => {
      console.warn('Vue warning:', msg)
      console.warn('Component trace:', trace)
    }
  }
  
  // Performance monitoring (development only)
  if (import.meta.env.DEV) {
    app.config.performance = true
  }
  
  return app
}

/**
 * Initialize application stores and services
 * 
 * Sets up initial state for authentication, UI preferences,
 * and other global application state.
 */
async function initializeApp() {
  try {
    // Initialize UI store first (theme, responsive settings)
    const uiStore = useUIStore()
    uiStore.initialize()
    
    // Initialize authentication store
    const authStore = useAuthStore()
    await authStore.initialize()
    
    console.log('Application initialized successfully')
  } catch (error) {
    console.error('Failed to initialize application:', error)
    
    // Show error to user
    const uiStore = useUIStore()
    uiStore.showError('Failed to initialize application. Please refresh the page.')
  }
}

/**
 * Setup global event listeners
 * 
 * Handles application-wide events like token expiration,
 * network status changes, and browser events.
 */
function setupGlobalEventListeners() {
  // Handle authentication token expiration
  window.addEventListener('auth:token-expired', async () => {
    const authStore = useAuthStore()
    const uiStore = useUIStore()
    
    await authStore.logout()
    uiStore.showWarning('Your session has expired. Please sign in again.')
    
    // Redirect to login if not already there
    if (router.currentRoute.value.name !== 'login') {
      router.push({ name: 'login' })
    }
  })
  
  // Handle network status changes
  window.addEventListener('online', () => {
    const uiStore = useUIStore()
    uiStore.showSuccess('Connection restored')
  })
  
  window.addEventListener('offline', () => {
    const uiStore = useUIStore()
    uiStore.showWarning('Connection lost. Some features may not work.')
  })
  
  // Handle unhandled promise rejections
  window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason)
    
    const uiStore = useUIStore()
    uiStore.showError('An unexpected error occurred. Please try again.')
    
    // Prevent the default browser behavior
    event.preventDefault()
  })
  
  // Handle visibility changes (tab switching)
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      // Tab became visible - could refresh data here
      console.log('Application became visible')
    }
  })
}

/**
 * Bootstrap the application
 * 
 * Main entry point that creates the app, initializes all services,
 * and mounts the application to the DOM.
 */
async function bootstrap() {
  try {
    // Show initial loading state
    const loadingElement = document.getElementById('app-loading')
    if (loadingElement) {
      loadingElement.style.display = 'flex'
    }
    
    // Create Vue application
    const app = await createVueApp()
    
    // Setup global event listeners
    setupGlobalEventListeners()
    
    // Mount the application
    app.mount('#app')
    
    // Initialize app state after mounting
    await initializeApp()
    
    // Hide loading screen
    if (loadingElement) {
      loadingElement.style.display = 'none'
    }
    
    console.log(`🚀 ${import.meta.env.VITE_APP_TITLE} v${import.meta.env.VITE_APP_VERSION} started successfully`)
    
  } catch (error) {
    console.error('Failed to bootstrap application:', error)
    
    // Show fallback error UI
    const appElement = document.getElementById('app')
    if (appElement) {
      appElement.innerHTML = `
        <div style="
          display: flex;
          flex-direction: column; 
          align-items: center; 
          justify-content: center; 
          height: 100vh; 
          font-family: system-ui;
          text-align: center;
          padding: 2rem;
        ">
          <h1 style="color: #f44336; margin-bottom: 1rem;">
            Application Failed to Start
          </h1>
          <p style="color: #666; margin-bottom: 2rem;">
            There was an error loading the application. Please refresh the page to try again.
          </p>
          <button 
            onclick="window.location.reload()" 
            style="
              background: #1976d2; 
              color: white; 
              border: none; 
              padding: 0.75rem 1.5rem; 
              border-radius: 4px; 
              cursor: pointer;
              font-size: 1rem;
            "
          >
            Refresh Page
          </button>
        </div>
      `
    }
  }
}

// Start the application
bootstrap()
