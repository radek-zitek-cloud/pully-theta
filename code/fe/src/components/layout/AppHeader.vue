/**
 * Application Header Component
 * 
 * Top navigation bar with app title, user menu, and theme toggle.
 * Responsive design with mobile-friendly navigation controls.
 */

<template>
  <VAppBar
    :elevation="1"
    color="surface"
    height="64"
    app
  >
    <!-- Sidebar Toggle Button -->
    <VAppBarNavIcon
      @click="uiStore.toggleSidebar"
      :aria-label="uiStore.sidebarOpen ? 'Close sidebar' : 'Open sidebar'"
    />

    <!-- App Title -->
    <VAppBarTitle class="text-h6 font-weight-bold">
      {{ appTitle }}
    </VAppBarTitle>

    <VSpacer />

    <!-- Theme Toggle Button -->
    <VBtn
      :icon="themeIcon"
      variant="text"
      @click="uiStore.toggleTheme"
      :aria-label="`Switch to ${nextTheme} theme`"
    />

    <!-- Notifications Button -->
    <VBtn
      icon="mdi-bell"
      variant="text"
      @click="showNotifications"
      :aria-label="notificationAriaLabel"
    >
      <VIcon>mdi-bell</VIcon>
      <VBadge
        v-if="uiStore.hasNotifications"
        :content="uiStore.notifications.length"
        color="error"
        floating
      />
    </VBtn>

    <!-- User Menu -->
    <VMenu v-if="authStore.isAuthenticated">
      <template #activator="{ props }">
        <VBtn
          v-bind="props"
          variant="text"
          class="ml-2"
          :aria-label="userMenuAriaLabel"
        >
          <VAvatar
            :size="32"
            color="primary"
            class="mr-2"
          >
            <span class="text-white font-weight-medium">
              {{ authStore.userInitials }}
            </span>
          </VAvatar>
          <span class="d-none d-sm-inline">
            {{ authStore.userFullName }}
          </span>
          <VIcon class="ml-1">mdi-chevron-down</VIcon>
        </VBtn>
      </template>

      <VList>
        <!-- User Info -->
        <VListItem>
          <template #prepend>
            <VAvatar color="primary">
              <span class="text-white font-weight-medium">
                {{ authStore.userInitials }}
              </span>
            </VAvatar>
          </template>
          <VListItemTitle class="font-weight-medium">
            {{ authStore.userFullName }}
          </VListItemTitle>
          <VListItemSubtitle>
            {{ authStore.user?.email }}
          </VListItemSubtitle>
        </VListItem>

        <VDivider />

        <!-- Profile Link -->
        <VListItem
          :to="{ name: 'profile' }"
          prepend-icon="mdi-account-circle"
        >
          <VListItemTitle>Profile</VListItemTitle>
        </VListItem>

        <!-- Settings Link -->
        <VListItem
          :to="{ name: 'settings' }"
          prepend-icon="mdi-cog"
        >
          <VListItemTitle>Settings</VListItemTitle>
        </VListItem>

        <VDivider />

        <!-- Logout Button -->
        <VListItem
          prepend-icon="mdi-logout"
          @click="handleLogout"
        >
          <VListItemTitle>Sign Out</VListItemTitle>
        </VListItem>
        
        <!-- Logout All Devices -->
        <VListItem
          prepend-icon="mdi-logout-variant"
          @click="handleLogoutAll"
        >
          <VListItemTitle>Sign Out All Devices</VListItemTitle>
        </VListItem>
      </VList>
    </VMenu>

    <!-- Login Button (when not authenticated) -->
    <VBtn
      v-else
      :to="{ name: 'login' }"
      color="primary"
      variant="elevated"
      prepend-icon="mdi-login"
    >
      Sign In
    </VBtn>
  </VAppBar>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore, useUIStore } from '@/stores'

// Store references
const authStore = useAuthStore()
const uiStore = useUIStore()
const router = useRouter()

// Computed properties
const appTitle = computed(() => {
  return import.meta.env.VITE_APP_TITLE || 'Pully Theta'
})

const themeIcon = computed(() => {
  const theme = uiStore.activeTheme
  return theme === 'dark' ? 'mdi-weather-night' : 'mdi-weather-sunny'
})

const nextTheme = computed(() => {
  return uiStore.activeTheme === 'dark' ? 'light' : 'dark'
})

const notificationAriaLabel = computed(() => {
  const count = uiStore.notifications.length
  return count > 0 
    ? `${count} notification${count > 1 ? 's' : ''}`
    : 'No notifications'
})

const userMenuAriaLabel = computed(() => {
  return `User menu for ${authStore.userFullName}`
})

// Methods

/**
 * Show notifications panel
 */
function showNotifications() {
  // Toggle notifications visibility or show notification panel
  if (uiStore.hasNotifications) {
    // For now, just clear notifications
    // In a real app, you might show a notification panel
    uiStore.clearNotifications()
  }
}

/**
 * Handle user logout
 */
async function handleLogout() {
  try {
    uiStore.setGlobalLoading(true)
    await authStore.logout()
    uiStore.showSuccess('Signed out successfully')
    router.push({ name: 'login' })
  } catch (error) {
    console.error('Logout failed:', error)
    uiStore.showError('Failed to sign out. Please try again.')
  } finally {
    uiStore.setGlobalLoading(false)
  }
}

/**
 * Handle logout from all devices
 */
async function handleLogoutAll() {
  const confirmed = await uiStore.showConfirmDialog({
    title: 'Sign Out All Devices',
    message: 'This will sign you out from all devices. Are you sure?',
    confirmText: 'Sign Out All',
    destructive: true
  })

  if (confirmed) {
    try {
      uiStore.setGlobalLoading(true)
      await authStore.logout(true)
      uiStore.showSuccess('Signed out from all devices')
      router.push({ name: 'login' })
    } catch (error) {
      console.error('Logout all failed:', error)
      uiStore.showError('Failed to sign out from all devices. Please try again.')
    } finally {
      uiStore.setGlobalLoading(false)
    }
  }
}
</script>

<style scoped>
.v-app-bar {
  backdrop-filter: blur(10px);
  background-color: rgba(var(--v-theme-surface), 0.9) !important;
}

.v-app-bar-title {
  cursor: pointer;
  transition: color 0.2s ease;
}

.v-app-bar-title:hover {
  color: rgb(var(--v-theme-primary));
}

.v-avatar {
  transition: transform 0.2s ease;
}

.v-avatar:hover {
  transform: scale(1.05);
}

/* Ensure proper spacing on mobile */
@media (max-width: 600px) {
  .v-app-bar-title {
    font-size: 1.1rem;
  }
  
  .v-btn {
    min-width: 40px;
  }
}
</style>
