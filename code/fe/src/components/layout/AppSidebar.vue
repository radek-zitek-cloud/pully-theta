/**
 * Application Sidebar Component
 * 
 * Navigation sidebar with expandable menu items and responsive behavior.
 * Supports both collapsed and expanded states with smooth transitions.
 */

<template>
  <VNavigationDrawer
    v-model="uiStore.sidebarOpen"
    :rail="!uiStore.sidebarOpen && !uiStore.isMobile"
    :temporary="uiStore.isMobile"
    :width="280"
    :rail-width="64"
    color="surface"
    elevation="2"
    app
  >
    <!-- Sidebar Header -->
    <VListItem
      class="sidebar-header"
      :class="{ 'sidebar-header--collapsed': !uiStore.sidebarOpen && !uiStore.isMobile }"
    >
      <template #prepend>
        <VAvatar
          color="primary"
          size="36"
        >
          <VIcon>mdi-account-circle</VIcon>
        </VAvatar>
      </template>

      <VListItemTitle 
        v-if="uiStore.sidebarOpen || uiStore.isMobile"
        class="font-weight-bold"
      >
        {{ authStore.userFullName || 'Guest User' }}
      </VListItemTitle>

      <VListItemSubtitle 
        v-if="uiStore.sidebarOpen || uiStore.isMobile"
        class="text-caption"
      >
        {{ authStore.user?.email || 'Not signed in' }}
      </VListItemSubtitle>

      <template #append>
        <VBtn
          v-if="!uiStore.isMobile"
          :icon="uiStore.sidebarOpen ? 'mdi-chevron-left' : 'mdi-chevron-right'"
          variant="text"
          size="small"
          @click="uiStore.toggleSidebar"
          :aria-label="uiStore.sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'"
        />
      </template>
    </VListItem>

    <VDivider />

    <!-- Navigation Menu -->
    <VList nav>
      <template v-for="item in navigationItems" :key="item.name">
        <!-- Regular menu item -->
        <VListItem
          v-if="item.showInMenu && (!item.requiresAuth || authStore.isAuthenticated)"
          :to="{ name: item.name }"
          :prepend-icon="item.icon"
          :title="item.title"
          :value="item.name"
          exact
          class="nav-item"
        >
          <VListItemTitle>{{ item.title }}</VListItemTitle>
          
          <!-- Tooltip for collapsed state -->
          <VTooltip
            v-if="!uiStore.sidebarOpen && !uiStore.isMobile"
            activator="parent"
            location="end"
          >
            {{ item.title }}
          </VTooltip>
        </VListItem>
      </template>
    </VList>

    <VSpacer />

    <!-- Bottom Section -->
    <VList nav>
      <VDivider />
      
      <!-- Help & Support -->
      <VListItem
        prepend-icon="mdi-help-circle"
        title="Help & Support"
        @click="showHelp"
      >
        <VListItemTitle>Help & Support</VListItemTitle>
        
        <VTooltip
          v-if="!uiStore.sidebarOpen && !uiStore.isMobile"
          activator="parent"
          location="end"
        >
          Help & Support
        </VTooltip>
      </VListItem>

      <!-- Version Info -->
      <VListItem
        v-if="uiStore.sidebarOpen || uiStore.isMobile"
        class="version-info"
      >
        <VListItemSubtitle class="text-center text-caption">
          v{{ appVersion }}
        </VListItemSubtitle>
      </VListItem>
    </VList>
  </VNavigationDrawer>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAuthStore, useUIStore } from '@/stores'
import type { NavigationRoute } from '@/types'

// Store references
const authStore = useAuthStore()
const uiStore = useUIStore()

// Computed properties
const appVersion = computed(() => {
  return import.meta.env.VITE_APP_VERSION || '1.0.0'
})

/**
 * Navigation menu items configuration
 * 
 * Defines the main navigation structure with icons, routes,
 * and authentication requirements.
 */
const navigationItems = computed<NavigationRoute[]>(() => [
  {
    name: 'dashboard',
    title: 'Dashboard',
    path: '/dashboard',
    icon: 'mdi-view-dashboard',
    requiresAuth: true,
    showInMenu: true,
    order: 1
  },
  {
    name: 'profile',
    title: 'Profile',
    path: '/profile',
    icon: 'mdi-account-circle',
    requiresAuth: true,
    showInMenu: true,
    order: 2
  },
  {
    name: 'settings',
    title: 'Settings',
    path: '/settings',
    icon: 'mdi-cog',
    requiresAuth: true,
    showInMenu: true,
    order: 3
  }
])

// Methods

/**
 * Show help and support information
 */
function showHelp() {
  uiStore.showInfo(
    'For support, please contact our team or visit the documentation.',
    {
      timeout: 8000,
      actions: [
        {
          label: 'Documentation',
          handler: () => {
            window.open('https://docs.example.com', '_blank')
          }
        }
      ]
    }
  )
}
</script>

<style scoped>
.sidebar-header {
  padding: 16px;
  min-height: 80px;
}

.sidebar-header--collapsed {
  justify-content: center;
  padding: 16px 12px;
}

.nav-item {
  margin: 2px 8px;
  border-radius: 8px;
  transition: all 0.2s ease;
}

.nav-item:hover {
  background-color: rgba(var(--v-theme-primary), 0.1);
}

.nav-item.v-list-item--active {
  background-color: rgba(var(--v-theme-primary), 0.15);
  color: rgb(var(--v-theme-primary));
}

.nav-item.v-list-item--active .v-icon {
  color: rgb(var(--v-theme-primary));
}

.version-info {
  opacity: 0.7;
  pointer-events: none;
}

/* Custom scrollbar for sidebar */
.v-navigation-drawer ::-webkit-scrollbar {
  width: 4px;
}

.v-navigation-drawer ::-webkit-scrollbar-track {
  background: transparent;
}

.v-navigation-drawer ::-webkit-scrollbar-thumb {
  background: rgba(var(--v-theme-on-surface), 0.2);
  border-radius: 2px;
}

.v-navigation-drawer ::-webkit-scrollbar-thumb:hover {
  background: rgba(var(--v-theme-on-surface), 0.3);
}

/* Responsive adjustments */
@media (max-width: 960px) {
  .sidebar-header {
    min-height: 72px;
  }
}
</style>
