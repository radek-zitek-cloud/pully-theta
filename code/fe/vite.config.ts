import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vuetify from 'vite-plugin-vuetify'
import { resolve } from 'path'

/**
 * Vite configuration for Vue.js application with Vuetify support
 * 
 * Features:
 * - Vue 3 with TypeScript support
 * - Vuetify 3 integration with theme customization
 * - Path aliases for clean imports
 * - Development server configuration
 * - Build optimizations for production
 * 
 * @see https://vitejs.dev/config/
 */
export default defineConfig({
  plugins: [
    vue(),
    // Vuetify plugin with tree-shaking support
    vuetify({
      autoImport: true
    })
  ],
  
  // Path aliases for cleaner imports
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
  
  // Development server configuration
  server: {
    port: 3000,
    open: true,
    cors: true,
    // Proxy API requests to the Go auth service
    proxy: {
      '/api': {
        target: 'http://localhost:6910',
        changeOrigin: true,
        secure: false,
        configure: (proxy, _options) => {
          proxy.on('error', (err, _req, _res) => {
            console.log('proxy error', err)
          })
          proxy.on('proxyReq', (proxyReq, req, _res) => {
            console.log('Sending Request to the Target:', req.method, req.url)
          })
          proxy.on('proxyRes', (proxyRes, req, _res) => {
            console.log('Received Response from the Target:', proxyRes.statusCode, req.url)
          })
        }
      }
    }
  },
  
  // Build configuration
  build: {
    target: 'esnext',
    sourcemap: true,
    // Optimize chunks for better caching
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['vue', 'vue-router', 'pinia'],
          ui: ['vuetify'],
          utils: ['axios', 'date-fns']
        }
      }
    }
  },
  
  // TypeScript configuration
  define: {
    __VUE_OPTIONS_API__: false,
    __VUE_PROD_DEVTOOLS__: false
  }
})
