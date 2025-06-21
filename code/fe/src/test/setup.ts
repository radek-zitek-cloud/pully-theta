/**
 * Vitest Test Setup
 * 
 * Global test configuration and setup for Vue 3 testing environment.
 * This file is run before all test files and configures the testing environment
 * with necessary polyfills, global utilities, and component testing setup.
 */

import { vi, expect } from 'vitest'
import { config } from '@vue/test-utils'

// Extend global interface for custom properties
declare global {
  interface Window {
    testUtils: {
      delay: (ms: number) => Promise<void>
      createMockUser: () => any
      createMockTokens: () => any
    }
  }
}

/**
 * Configure Vue Test Utils global properties
 * 
 * Sets up global configuration that will be available
 * in all component tests without manual setup.
 */
config.global.config.warnHandler = () => {
  // Suppress Vue warnings during tests
}

/**
 * Mock IntersectionObserver
 * 
 * JSDOM doesn't provide IntersectionObserver, which is used by some
 * Vuetify components. This mock provides a basic implementation.
 */
global.IntersectionObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
  root: null,
  rootMargin: '',
  thresholds: []
}))

/**
 * Mock ResizeObserver
 * 
 * JSDOM doesn't provide ResizeObserver, which is used by some
 * Vuetify components for responsive behavior.
 */
global.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn()
}))

/**
 * Mock window.matchMedia
 * 
 * JSDOM doesn't provide matchMedia, which is used for responsive
 * design queries in Vuetify components.
 */
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn()
  }))
})

/**
 * Mock localStorage
 * 
 * Provides a mock implementation of localStorage for testing
 * auth tokens and other persistent state.
 */
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
  length: 0,
  key: vi.fn()
}

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock
})

/**
 * Mock sessionStorage
 * 
 * Provides a mock implementation of sessionStorage for testing
 * temporary state storage.
 */
const sessionStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
  length: 0,
  key: vi.fn()
}

Object.defineProperty(window, 'sessionStorage', {
  value: sessionStorageMock
})

/**
 * Console suppression for clean test output
 * 
 * Suppresses expected console warnings during tests to keep
 * test output clean while still allowing intentional logging.
 */
const originalConsoleWarn = console.warn
console.warn = (...args: any[]) => {
  // Suppress known Vuetify warnings in tests
  if (args[0]?.includes && (
    args[0].includes('[Vuetify]') ||
    args[0].includes('Vue warn')
  )) {
    return
  }
  originalConsoleWarn.apply(console, args)
}

/**
 * Global test utilities
 * 
 * Common utilities that can be used across all test files
 * without importing them individually.
 */
;(globalThis as any).testUtils = {
  /**
   * Creates a delay for async testing
   * @param ms - Milliseconds to delay
   */
  delay: (ms: number) => new Promise(resolve => setTimeout(resolve, ms)),
  
  /**
   * Creates a mock user object for testing
   */
  createMockUser: () => ({
    id: 1,
    username: 'testuser',
    email: 'test@example.com',
    first_name: 'Test',
    last_name: 'User',
    is_email_verified: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  }),
  
  /**
   * Creates mock JWT tokens for testing
   */
  createMockTokens: () => ({
    access_token: 'mock.access.token',
    refresh_token: 'mock.refresh.token',
    expires_in: 3600,
    token_type: 'Bearer'
  })
}

/**
 * Custom matchers
 * 
 * Extend Vitest matchers with Vue/Vuetify specific assertions
 */
expect.extend({
  /**
   * Checks if a Vue component has emitted a specific event
   */
  toHaveEmitted(received: any, eventName: string) {
    const pass = received.emitted && received.emitted(eventName)
    return {
      pass,
      message: () => pass 
        ? `Expected component not to have emitted ${eventName}`
        : `Expected component to have emitted ${eventName}`
    }
  }
})

// Export setup utilities for manual use in tests
export {
  localStorageMock,
  sessionStorageMock
}
