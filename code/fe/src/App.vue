/**
 * Main Application Component
 * 
 * Root Vue component that provides the main application layout structure.
 * Includes header, sidebar navigation, main content area, and footer.
 * Handles responsive design and theme switching.
 */

<template>
  <VApp>
    <!-- Global Loading Overlay -->
    <VOverlay
      v-model="uiStore.isGlobalLoading"
      class="align-center justify-center"
      persistent
    >
      <VProgressCircular
        color="primary"
        indeterminate
        size="64"
      />
    </VOverlay>

    <!-- Main Application Layout -->
    <VLayout v-if="!isAuthRoute">
      <!-- App Header -->
      <AppHeader />

      <!-- Sidebar Navigation -->
      <AppSidebar />

      <!-- Main Content Area -->
      <VMain>
        <VContainer fluid>
          <!-- Page Loading Bar -->
          <VProgressLinear
            v-if="uiStore.isPageLoading"
            color="primary"
            indeterminate
            absolute
            top
          />
          
          <!-- Router View with Transitions -->
          <RouterView v-slot="{ Component, route }">
            <Transition
              :name="getTransitionName(route)"
              mode="out-in"
              appear
            >
              <component
                :is="Component"
                :key="route.path"
              />
            </Transition>
          </RouterView>
        </VContainer>
      </VMain>

      <!-- App Footer -->
      <AppFooter />
    </VLayout>

    <!-- Auth Layout (Login/Register) -->
    <RouterView v-else />

    <!-- Global Notifications -->
    <NotificationSystem />

    <!-- Global Confirmation Dialog -->
    <ConfirmationDialog />
  </VApp>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { useUIStore } from '@/stores'

// Import layout components
import AppHeader from '@/components/layout/AppHeader.vue'
import AppSidebar from '@/components/layout/AppSidebar.vue'
import AppFooter from '@/components/layout/AppFooter.vue'
import NotificationSystem from '@/components/common/NotificationSystem.vue'
import ConfirmationDialog from '@/components/common/ConfirmationDialog.vue'

// Store references
const uiStore = useUIStore()
const route = useRoute()

// Computed properties
const isAuthRoute = computed(() => {
  return route.path.startsWith('/auth')
})

/**
 * Get transition name based on route navigation
 * 
 * @param currentRoute - Current route object
 * @returns Transition name for CSS animations
 */
function getTransitionName(currentRoute: any): string {
  // Use different transitions based on route meta or path
  if (currentRoute.meta?.transition) {
    return currentRoute.meta.transition
  }
  
  // Default slide transition
  return 'slide-x-transition'
}

/**
 * Handle keyboard shortcuts
 * 
 * @param event - Keyboard event
 */
function handleKeyboardShortcuts(event: KeyboardEvent) {
  // Toggle sidebar with Ctrl/Cmd + B
  if ((event.ctrlKey || event.metaKey) && event.key === 'b') {
    event.preventDefault()
    uiStore.toggleSidebar()
  }
  
  // Toggle theme with Ctrl/Cmd + Shift + T
  if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key === 'T') {
    event.preventDefault()
    uiStore.toggleTheme()
  }
  
  // Close notifications with Escape
  if (event.key === 'Escape' && uiStore.hasNotifications) {
    uiStore.clearNotifications()
  }
}

// Lifecycle hooks
onMounted(() => {
  // Add keyboard shortcuts
  document.addEventListener('keydown', handleKeyboardShortcuts)
  
  // Apply initial theme
  uiStore.applyTheme()
})

onUnmounted(() => {
  // Clean up event listeners
  document.removeEventListener('keydown', handleKeyboardShortcuts)
})
</script>

<style scoped>
/**
 * Page transition animations
 */
.slide-x-transition-enter-active,
.slide-x-transition-leave-active {
  transition: all 0.3s ease-in-out;
}

.slide-x-transition-enter-from {
  opacity: 0;
  transform: translateX(20px);
}

.slide-x-transition-leave-to {
  opacity: 0;
  transform: translateX(-20px);
}

.fade-transition-enter-active,
.fade-transition-leave-active {
  transition: opacity 0.3s ease-in-out;
}

.fade-transition-enter-from,
.fade-transition-leave-to {
  opacity: 0;
}

/**
 * Responsive container adjustments
 */
.v-container {
  max-width: 1400px;
}

@media (max-width: 960px) {
  .v-container {
    padding: 16px;
  }
}
</style>
