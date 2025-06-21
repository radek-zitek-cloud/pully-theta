/// <reference types="vite/client" />

/**
 * Type declarations for environment variables and Vue SFC imports
 * This file provides TypeScript support for Vite environment variables
 * and Vue Single File Components.
 */

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

/**
 * Environment variables interface
 * Add your environment variables here for better type safety
 */
interface ImportMetaEnv {
  readonly VITE_API_BASE_URL: string
  readonly VITE_APP_TITLE: string
  readonly VITE_APP_VERSION: string
  readonly VITE_ENABLE_MOCK_API: string
  readonly VITE_JWT_SECRET: string
  readonly MODE: string
  readonly BASE_URL: string
  readonly PROD: boolean
  readonly DEV: boolean
  readonly SSR: boolean
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
