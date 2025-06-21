/**
 * Vue Router Configuration
 * 
 * Defines application routes with authentication guards, meta information,
 * and lazy loading for optimal performance. Implements proper navigation
 * guards for protected routes and authentication state management.
 */

import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/stores/auth.store'
import { useUIStore } from '@/stores/ui.store'
import type { RouteMeta } from '@/types'

/**
 * Application routes configuration
 * 
 * Routes are organized with:
 * - Lazy loading for code splitting
 * - Authentication guards via meta.requiresAuth
 * - Proper titles and metadata
 * - Icon references for navigation
 */
const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'home',
    redirect: '/dashboard',
    meta: {
      title: 'Home',
      requiresAuth: true
    } as RouteMeta
  },
  
  {
    path: '/dashboard',
    name: 'dashboard',
    component: () => import('@/views/DashboardView.vue'),
    meta: {
      title: 'Dashboard',
      requiresAuth: true,
      icon: 'mdi-view-dashboard',
      showInBreadcrumbs: true
    } as RouteMeta
  },
  
  // Authentication routes
  {
    path: '/auth',
    name: 'auth',
    component: () => import('@/layouts/AuthLayout.vue'),
    redirect: '/auth/login',
    meta: {
      requiresAuth: false,
      layout: 'auth'
    } as RouteMeta,
    children: [
      {
        path: 'login',
        name: 'login',
        component: () => import('@/views/auth/LoginView.vue'),
        meta: {
          title: 'Sign In',
          requiresAuth: false
        } as RouteMeta
      },
      {
        path: 'register',
        name: 'register',
        component: () => import('@/views/auth/RegisterView.vue'),
        meta: {
          title: 'Sign Up',
          requiresAuth: false
        } as RouteMeta
      },
      {
        path: 'forgot-password',
        name: 'forgot-password',
        component: () => import('@/views/auth/ForgotPasswordView.vue'),
        meta: {
          title: 'Reset Password',
          requiresAuth: false
        } as RouteMeta
      },
      {
        path: 'reset-password',
        name: 'reset-password',
        component: () => import('@/views/auth/ResetPasswordView.vue'),
        meta: {
          title: 'Set New Password',
          requiresAuth: false
        } as RouteMeta
      }
    ]
  },
  
  // User profile routes
  {
    path: '/profile',
    name: 'profile',
    component: () => import('@/views/ProfileView.vue'),
    meta: {
      title: 'Profile',
      requiresAuth: true,
      icon: 'mdi-account-circle',
      showInBreadcrumbs: true
    } as RouteMeta
  },
  
  {
    path: '/profile/edit',
    name: 'edit-profile',
    component: () => import('@/views/EditProfileView.vue'),
    meta: {
      title: 'Edit Profile',
      requiresAuth: true,
      showInBreadcrumbs: true
    } as RouteMeta
  },
  
  // Change password route
  {
    path: '/change-password',
    name: 'change-password',
    component: () => import('@/views/ChangePasswordView.vue'),
    meta: {
      title: 'Change Password',
      requiresAuth: true,
      showInBreadcrumbs: true,
      icon: 'mdi-lock-reset'
    } as RouteMeta
  },
  
  // Settings routes
  {
    path: '/settings',
    name: 'settings',
    component: () => import('@/views/SettingsView.vue'),
    meta: {
      title: 'Settings',
      requiresAuth: true,
      icon: 'mdi-cog',
      showInBreadcrumbs: true
    } as RouteMeta
  },
  
  // Error routes
  {
    path: '/unauthorized',
    name: 'unauthorized',
    component: () => import('@/views/UnauthorizedView.vue'),
    meta: {
      title: 'Unauthorized',
      requiresAuth: false
    } as RouteMeta
  },
  
  {
    path: '/not-found',
    name: 'not-found',
    component: () => import('@/views/NotFoundView.vue'),
    meta: {
      title: 'Page Not Found',
      requiresAuth: false
    } as RouteMeta
  },
  
  // Catch-all redirect to not found
  {
    path: '/:pathMatch(.*)*',
    redirect: '/not-found'
  }
]

/**
 * Create router instance with history mode and scroll behavior
 */
const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  
  // Scroll behavior for better UX
  scrollBehavior(to, _from, savedPosition) {
    if (savedPosition) {
      return savedPosition
    } else if (to.hash) {
      return {
        el: to.hash,
        behavior: 'smooth'
      }
    } else {
      return { top: 0 }
    }
  }
})

/**
 * Global navigation guard for authentication
 * 
 * Checks authentication status before navigating to protected routes.
 * Redirects unauthenticated users to login page and handles route titles.
 */
router.beforeEach(async (to, _from, next) => {
  const authStore = useAuthStore()
  const uiStore = useUIStore()
  
  // Show page loading
  uiStore.setPageLoading(true)
  
  // Set document title
  const title = to.meta?.title as string
  if (title) {
    document.title = `${title} - ${import.meta.env.VITE_APP_TITLE}`
  } else {
    document.title = import.meta.env.VITE_APP_TITLE
  }
  
  // Check if route requires authentication
  const requiresAuth = to.meta?.requiresAuth as boolean
  const isAuthenticated = authStore.isAuthenticated
  
  if (requiresAuth && !isAuthenticated) {
    // Try to initialize auth from stored tokens
    const initialized = await authStore.initialize()
    
    if (!initialized) {
      // Redirect to login with return path
      const returnPath = to.fullPath !== '/auth/login' ? to.fullPath : undefined
      next({
        name: 'login',
        query: returnPath ? { redirect: returnPath } : undefined
      })
      return
    }
  }
  
  // Redirect authenticated users away from auth pages
  if (!requiresAuth && isAuthenticated && to.path.startsWith('/auth')) {
    const redirectPath = (to.query.redirect as string) || '/dashboard'
    next(redirectPath)
    return
  }
  
  next()
})

/**
 * Global after navigation hook
 * 
 * Handles cleanup after navigation is complete.
 */
router.afterEach((to, from) => {
  const uiStore = useUIStore()
  
  // Hide page loading
  uiStore.setPageLoading(false)
  
  // Close mobile sidebar after navigation
  if (uiStore.isMobile && uiStore.sidebarOpen) {
    uiStore.setSidebarOpen(false)
  }
  
  // Log navigation in development
  if (import.meta.env.DEV) {
    console.log(`Navigated from ${from.path} to ${to.path}`)
  }
})

/**
 * Global error handler for router errors
 */
router.onError((error) => {
  console.error('Router error:', error)
  
  const uiStore = useUIStore()
  uiStore.setPageLoading(false)
  uiStore.showError('Navigation error occurred. Please try again.')
})

export default router
