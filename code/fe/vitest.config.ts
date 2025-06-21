import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

/**
 * Vitest configuration for Vue.js application testing
 * 
 * Features:
 * - Vue 3 component testing support
 * - JSDOM environment for DOM testing
 * - Path aliases matching main Vite config
 * - Global test utilities
 * - CSS handling for component testing
 * 
 * Note: Vuetify components require special handling due to CSS imports.
 * For testing Vuetify components, use the global Vuetify instance
 * configured in the test setup file.
 * 
 * @see https://vitest.dev/config/
 */
export default defineConfig({
  plugins: [
    vue()
  ],
  
  // Match path aliases from main Vite config
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@/components': resolve(__dirname, 'src/components'),
      '@/views': resolve(__dirname, 'src/views'),
      '@/stores': resolve(__dirname, 'src/stores'),
      '@/services': resolve(__dirname, 'src/services'),
      '@/types': resolve(__dirname, 'src/types'),
      '@/utils': resolve(__dirname, 'src/utils'),
      '@/composables': resolve(__dirname, 'src/composables')
    }
  },
  
  // Test configuration
  test: {
    // Enable global test utilities (describe, it, expect, etc.)
    globals: true,
    
    // Use JSDOM environment for DOM testing
    environment: 'jsdom',
    
    // Setup files to run before tests
    setupFiles: ['./src/test/setup.ts'],
    
    // Include test files
    include: [
      'src/**/*.{test,spec}.{js,ts,tsx}',
      'tests/**/*.{test,spec}.{js,ts,tsx}'
    ],
    
    // Exclude files from testing
    exclude: [
      'node_modules',
      'dist',
      '.idea',
      '.git',
      '.cache'
    ],
    
    // CSS handling - mock CSS imports for testing
    css: {
      modules: {
        classNameStrategy: 'non-scoped'
      }
    },
    
    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'src/test/',
        '**/*.d.ts',
        '**/*.config.*',
        'dist/'
      ],
      thresholds: {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80
        }
      }
    },
    
    // Test timeout (in milliseconds)
    testTimeout: 10000,
    
    // Hook timeout (in milliseconds)
    hookTimeout: 10000
  }
})
