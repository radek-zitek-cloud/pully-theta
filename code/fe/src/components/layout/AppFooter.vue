/**
 * Application Footer Component
 * 
 * Simple footer with status information, links, and app metadata.
 * Displays copyright, version, and connection status.
 */

<template>
  <VFooter
    color="surface"
    elevation="1"
    height="48"
    app
  >
    <VContainer class="d-flex align-center justify-space-between py-0">
      <!-- Left section: Status indicators -->
      <div class="d-flex align-center">
        <!-- Connection status -->
        <VChip
          :color="connectionStatus.color"
          size="small"
          variant="flat"
          class="mr-3"
        >
          <VIcon 
            :icon="connectionStatus.icon" 
            size="small" 
            class="mr-1"
          />
          {{ connectionStatus.text }}
        </VChip>

        <!-- Authentication status -->
        <VChip
          v-if="authStore.isAuthenticated"
          color="success"
          size="small"
          variant="flat"
          class="mr-3"
        >
          <VIcon icon="mdi-check-circle" size="small" class="mr-1" />
          Signed In
        </VChip>

        <!-- Environment indicator (development only) -->
        <VChip
          v-if="isDevelopment"
          color="warning"
          size="small"
          variant="outlined"
          class="mr-3"
        >
          <VIcon icon="mdi-dev-to" size="small" class="mr-1" />
          Development
        </VChip>
      </div>

      <!-- Center section: Copyright -->
      <div class="text-center d-none d-md-block">
        <span class="text-caption text-medium-emphasis">
          © {{ currentYear }} {{ appName }}. All rights reserved.
        </span>
      </div>

      <!-- Right section: Version and links -->
      <div class="d-flex align-center">
        <!-- App version -->
        <span class="text-caption text-medium-emphasis mr-4">
          v{{ appVersion }}
        </span>

        <!-- Quick links -->
        <div class="d-flex align-center">
          <VBtn
            icon="mdi-information"
            variant="text"
            size="small"
            @click="showAppInfo"
            aria-label="App information"
          />
          
          <VBtn
            icon="mdi-github"
            variant="text"
            size="small"
            href="https://github.com/your-org/pully-theta"
            target="_blank"
            aria-label="View source code"
          />
        </div>
      </div>
    </VContainer>
  </VFooter>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useAuthStore, useUIStore } from '@/stores'

// Store references
const authStore = useAuthStore()
const uiStore = useUIStore()

// Reactive state
const isOnline = ref(navigator.onLine)

// Computed properties
const appName = computed(() => {
  return import.meta.env.VITE_APP_TITLE || 'Pully Theta'
})

const appVersion = computed(() => {
  return import.meta.env.VITE_APP_VERSION || '1.0.0'
})

const currentYear = computed(() => {
  return new Date().getFullYear()
})

const isDevelopment = computed(() => {
  return import.meta.env.DEV
})

const connectionStatus = computed(() => {
  if (!isOnline.value) {
    return {
      color: 'error',
      icon: 'mdi-wifi-off',
      text: 'Offline'
    }
  }
  
  return {
    color: 'success',
    icon: 'mdi-wifi',
    text: 'Online'
  }
})

// Methods

/**
 * Show application information dialog
 */
function showAppInfo() {
  const buildDate = new Date().toLocaleDateString()
  const environment = import.meta.env.MODE
  
  uiStore.showInfo(
    `${appName.value} v${appVersion.value}\n\nEnvironment: ${environment}\nBuild: ${buildDate}`,
    {
      timeout: 10000,
      actions: [
        {
          label: 'GitHub',
          handler: () => {
            window.open('https://github.com/your-org/pully-theta', '_blank')
          }
        }
      ]
    }
  )
}

/**
 * Handle online status change
 */
function handleOnlineStatusChange() {
  isOnline.value = navigator.onLine
  
  if (isOnline.value) {
    uiStore.showSuccess('Connection restored')
  } else {
    uiStore.showWarning('Connection lost. Working offline.')
  }
}

// Lifecycle hooks
onMounted(() => {
  // Listen for online/offline events
  window.addEventListener('online', handleOnlineStatusChange)
  window.addEventListener('offline', handleOnlineStatusChange)
})

onUnmounted(() => {
  // Clean up event listeners
  window.removeEventListener('online', handleOnlineStatusChange)
  window.removeEventListener('offline', handleOnlineStatusChange)
})
</script>

<style scoped>
.v-footer {
  backdrop-filter: blur(10px);
  background-color: rgba(var(--v-theme-surface), 0.9) !important;
  border-top: 1px solid rgba(var(--v-theme-on-surface), 0.12);
}

.v-chip {
  font-size: 0.75rem;
  height: 24px;
}

.v-btn {
  opacity: 0.7;
  transition: opacity 0.2s ease;
}

.v-btn:hover {
  opacity: 1;
}

/* Mobile adjustments */
@media (max-width: 960px) {
  .v-container {
    padding: 0 16px;
  }
  
  .text-caption {
    font-size: 0.7rem;
  }
}

/* Extra small screens */
@media (max-width: 600px) {
  .v-container {
    padding: 0 8px;
  }
  
  .v-chip {
    font-size: 0.7rem;
    height: 20px;
  }
  
  .v-chip .v-icon {
    font-size: 0.8rem;
  }
}
</style>
