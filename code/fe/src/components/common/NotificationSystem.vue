/**
 * Notification System Component
 * 
 * Global notification system using Vuetify snackbars.
 * Displays multiple notifications with different types and actions.
 * Supports auto-dismiss, manual dismiss, and action buttons.
 */

<template>
  <div class="notification-system">
    <VSnackbar
      v-for="notification in uiStore.notifications"
      :key="notification.id"
      v-model="notification.visible"
      :color="getNotificationColor(notification.type)"
      :timeout="notification.timeout || 5000"
      :multi-line="isMultiLine(notification.message)"
      location="bottom right"
      :offset-y="getOffsetY(notification)"
      elevation="6"
      @update:model-value="handleNotificationUpdate(notification.id, $event)"
    >
      <div class="d-flex align-center">
        <!-- Notification Icon -->
        <VIcon
          :icon="getNotificationIcon(notification.type)"
          class="mr-3"
          size="20"
        />
        
        <!-- Notification Message -->
        <div class="flex-grow-1">
          <div class="notification-message">
            {{ notification.message }}
          </div>
          
          <!-- Notification Timestamp -->
          <div 
            v-if="showTimestamp"
            class="notification-timestamp text-caption"
          >
            {{ formatNotificationTime(notification.createdAt) }}
          </div>
        </div>
      </div>

      <!-- Notification Actions -->
      <template #actions>
        <div class="d-flex align-center ml-2">
          <!-- Custom Action Buttons -->
          <VBtn
            v-for="action in notification.actions"
            :key="action.label"
            :color="action.color || 'white'"
            variant="text"
            size="small"
            @click="handleActionClick(notification.id, action)"
          >
            {{ action.label }}
          </VBtn>

          <!-- Dismiss Button -->
          <VBtn
            v-if="notification.dismissible"
            icon="mdi-close"
            variant="text"
            size="small"
            @click="dismissNotification(notification.id)"
            aria-label="Dismiss notification"
          />
        </div>
      </template>
    </VSnackbar>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useUIStore } from '@/stores'
import type { NotificationState, NotificationAction } from '@/types'

// Store reference
const uiStore = useUIStore()

// Props
interface Props {
  showTimestamp?: boolean
  maxNotifications?: number
}

const props = withDefaults(defineProps<Props>(), {
  showTimestamp: false,
  maxNotifications: 5
})

// Computed properties
const visibleNotifications = computed(() => {
  return uiStore.notifications
    .slice(-props.maxNotifications)
    .map((notification, index) => ({
      ...notification,
      visible: true,
      stackIndex: index
    }))
})

// Methods

/**
 * Get notification color based on type
 * 
 * @param type - Notification type
 * @returns Vuetify color name
 */
function getNotificationColor(type: NotificationState['type']): string {
  const colorMap = {
    success: 'success',
    error: 'error',
    warning: 'warning',
    info: 'info'
  }
  return colorMap[type] || 'info'
}

/**
 * Get notification icon based on type
 * 
 * @param type - Notification type
 * @returns Material Design Icon name
 */
function getNotificationIcon(type: NotificationState['type']): string {
  const iconMap = {
    success: 'mdi-check-circle',
    error: 'mdi-alert-circle',
    warning: 'mdi-alert',
    info: 'mdi-information'
  }
  return iconMap[type] || 'mdi-information'
}

/**
 * Check if notification message requires multi-line display
 * 
 * @param message - Notification message
 * @returns True if message is long or contains line breaks
 */
function isMultiLine(message: string): boolean {
  return message.length > 60 || message.includes('\n')
}

/**
 * Get Y offset for stacked notifications
 * 
 * @param notification - Notification object
 * @returns Offset value in pixels
 */
function getOffsetY(notification: any): number {
  const baseOffset = 20
  const stackOffset = 80
  return baseOffset + (notification.stackIndex * stackOffset)
}

/**
 * Format notification timestamp for display
 * 
 * @param timestamp - Notification creation timestamp
 * @returns Formatted time string
 */
function formatNotificationTime(timestamp: number): string {
  const now = Date.now()
  const diff = now - timestamp
  
  if (diff < 60000) { // Less than 1 minute
    return 'Just now'
  } else if (diff < 3600000) { // Less than 1 hour
    const minutes = Math.floor(diff / 60000)
    return `${minutes}m ago`
  } else if (diff < 86400000) { // Less than 1 day
    const hours = Math.floor(diff / 3600000)
    return `${hours}h ago`
  } else {
    return new Date(timestamp).toLocaleDateString()
  }
}

/**
 * Handle notification visibility update
 * 
 * @param notificationId - Notification ID
 * @param visible - New visibility state
 */
function handleNotificationUpdate(notificationId: string, visible: boolean) {
  if (!visible) {
    dismissNotification(notificationId)
  }
}

/**
 * Dismiss a notification
 * 
 * @param notificationId - Notification ID to dismiss
 */
function dismissNotification(notificationId: string) {
  uiStore.dismissNotification(notificationId)
}

/**
 * Handle action button click
 * 
 * @param notificationId - Notification ID
 * @param action - Action object
 */
function handleActionClick(notificationId: string, action: NotificationAction) {
  try {
    action.handler()
  } catch (error) {
    console.error('Error executing notification action:', error)
  } finally {
    // Optionally dismiss notification after action
    dismissNotification(notificationId)
  }
}
</script>

<style scoped>
.notification-system {
  pointer-events: none;
}

.v-snackbar {
  pointer-events: auto;
}

.notification-message {
  font-size: 0.875rem;
  line-height: 1.4;
  white-space: pre-wrap;
}

.notification-timestamp {
  opacity: 0.8;
  margin-top: 4px;
}

/* Custom snackbar styling */
:deep(.v-snackbar__wrapper) {
  border-radius: 8px;
  backdrop-filter: blur(10px);
}

:deep(.v-snackbar__content) {
  padding: 16px 20px;
}

/* Notification type specific styling */
:deep(.v-snackbar--variant-flat.bg-success) {
  background-color: rgba(var(--v-theme-success), 0.9) !important;
}

:deep(.v-snackbar--variant-flat.bg-error) {
  background-color: rgba(var(--v-theme-error), 0.9) !important;
}

:deep(.v-snackbar--variant-flat.bg-warning) {
  background-color: rgba(var(--v-theme-warning), 0.9) !important;
}

:deep(.v-snackbar--variant-flat.bg-info) {
  background-color: rgba(var(--v-theme-info), 0.9) !important;
}

/* Animation for stacked notifications */
.v-snackbar {
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

/* Responsive adjustments */
@media (max-width: 600px) {
  :deep(.v-snackbar) {
    left: 16px !important;
    right: 16px !important;
    bottom: 16px !important;
    width: auto !important;
    max-width: none !important;
  }
  
  .notification-message {
    font-size: 0.8rem;
  }
}
</style>
