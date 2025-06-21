/**
 * Settings View Component
 * 
 * Comprehensive application settings interface including account settings,
 * security preferences, notification controls, and system preferences.
 */

<template>
  <div class="settings-view">
    <!-- Header -->
    <div class="mb-6">
      <h1 class="text-h4 font-weight-bold mb-2">Settings</h1>
      <p class="text-body-1 text-medium-emphasis">
        Manage your account, security, and application preferences
      </p>
    </div>

    <!-- Settings Navigation -->
    <VTabs
      v-model="activeTab"
      class="mb-6"
      color="primary"
      show-arrows
    >
      <VTab value="account">
        <VIcon start>mdi-account-cog</VIcon>
        Account
      </VTab>
      <VTab value="security">
        <VIcon start>mdi-shield-check</VIcon>
        Security
      </VTab>
      <VTab value="notifications">
        <VIcon start>mdi-bell-cog</VIcon>
        Notifications
      </VTab>
      <VTab value="appearance">
        <VIcon start>mdi-palette</VIcon>
        Appearance
      </VTab>
      <VTab value="privacy">
        <VIcon start>mdi-lock</VIcon>
        Privacy
      </VTab>
      <VTab value="advanced">
        <VIcon start>mdi-cog</VIcon>
        Advanced
      </VTab>
    </VTabs>

    <VWindow v-model="activeTab">
      <!-- Account Settings -->
      <VWindowItem value="account">
        <VRow>
          <VCol cols="12" md="8">
            <VCard elevation="2" class="mb-6">
              <VCardTitle>Account Information</VCardTitle>
              <VCardText>
                <VList>
                  <VListItem class="px-0">
                    <VListItemTitle>Profile</VListItemTitle>
                    <VListItemSubtitle>
                      Update your personal information and profile picture
                    </VListItemSubtitle>
                    <template #append>
                      <VBtn
                        :to="{ name: 'edit-profile' }"
                        variant="outlined"
                        size="small"
                      >
                        Edit
                      </VBtn>
                    </template>
                  </VListItem>
                  
                  <VDivider class="my-4" />
                  
                  <VListItem class="px-0">
                    <VListItemTitle>Email Preferences</VListItemTitle>
                    <VListItemSubtitle>
                      {{ user?.email }}
                    </VListItemSubtitle>
                    <template #append>
                      <VChip
                        :color="user?.is_email_verified ? 'success' : 'warning'"
                        size="small"
                        variant="tonal"
                      >
                        {{ user?.is_email_verified ? 'Verified' : 'Unverified' }}
                      </VChip>
                    </template>
                  </VListItem>
                </VList>
              </VCardText>
            </VCard>

            <VCard elevation="2">
              <VCardTitle>Danger Zone</VCardTitle>
              <VCardText>
                <VAlert
                  color="error"
                  variant="tonal"
                  class="mb-4"
                >
                  <VAlertTitle>Delete Account</VAlertTitle>
                  Once you delete your account, there is no going back. 
                  Please be certain.
                </VAlert>
                
                <VBtn
                  color="error"
                  variant="outlined"
                  prepend-icon="mdi-delete-forever"
                  @click="deleteAccount"
                >
                  Delete Account
                </VBtn>
              </VCardText>
            </VCard>
          </VCol>
        </VRow>
      </VWindowItem>

      <!-- Security Settings -->
      <VWindowItem value="security">
        <VRow>
          <VCol cols="12" md="8">
            <VCard elevation="2" class="mb-6">
              <VCardTitle>Password & Authentication</VCardTitle>
              <VCardText>
                <VList>
                  <VListItem class="px-0">
                    <VListItemTitle>Password</VListItemTitle>
                    <VListItemSubtitle>
                      Last changed {{ formatDate(user?.password_changed_at) }}
                    </VListItemSubtitle>
                    <template #append>
                      <VBtn
                        variant="outlined"
                        size="small"
                        @click="changePassword"
                      >
                        Change
                      </VBtn>
                    </template>
                  </VListItem>
                  
                  <VDivider class="my-4" />
                  
                  <VListItem class="px-0">
                    <VListItemTitle>Two-Factor Authentication</VListItemTitle>
                    <VListItemSubtitle>
                      {{ user?.two_factor_enabled ? 'Enabled' : 'Add an extra layer of security' }}
                    </VListItemSubtitle>
                    <template #append>
                      <VBtn
                        v-if="!user?.two_factor_enabled"
                        color="success"
                        variant="outlined"
                        size="small"
                        @click="enable2FA"
                      >
                        Enable
                      </VBtn>
                      <VBtn
                        v-else
                        color="error"
                        variant="outlined"
                        size="small"
                        @click="disable2FA"
                      >
                        Disable
                      </VBtn>
                    </template>
                  </VListItem>
                </VList>
              </VCardText>
            </VCard>

            <VCard elevation="2">
              <VCardTitle>Active Sessions</VCardTitle>
              <VCardText>
                <VList>
                  <VListItem
                    v-for="session in activeSessions"
                    :key="session.id"
                    class="px-0"
                  >
                    <template #prepend>
                      <VAvatar color="primary" variant="tonal">
                        <VIcon>{{ session.device_icon }}</VIcon>
                      </VAvatar>
                    </template>
                    
                    <VListItemTitle>{{ session.device_name }}</VListItemTitle>
                    <VListItemSubtitle>
                      {{ session.location }} • {{ formatDateTime(session.last_active) }}
                    </VListItemSubtitle>
                    
                    <template #append>
                      <VChip
                        v-if="session.is_current"
                        color="success"
                        size="small"
                        variant="tonal"
                      >
                        Current
                      </VChip>
                      <VBtn
                        v-else
                        variant="text"
                        size="small"
                        color="error"
                        @click="terminateSession(session.id)"
                      >
                        Terminate
                      </VBtn>
                    </template>
                  </VListItem>
                </VList>
                
                <VBtn
                  color="warning"
                  variant="outlined"
                  prepend-icon="mdi-logout-variant"
                  class="mt-4"
                  @click="logoutAllSessions"
                >
                  Logout All Sessions
                </VBtn>
              </VCardText>
            </VCard>
          </VCol>
        </VRow>
      </VWindowItem>

      <!-- Notification Settings -->
      <VWindowItem value="notifications">
        <VRow>
          <VCol cols="12" md="8">
            <VCard elevation="2">
              <VCardTitle>Notification Preferences</VCardTitle>
              <VCardText>
                <div class="mb-6">
                  <h3 class="text-h6 mb-4">Email Notifications</h3>
                  <VSwitch
                    v-model="settings.notifications.email.account_activity"
                    label="Account Activity"
                    color="primary"
                    hide-details
                    class="mb-2"
                  />
                  <VSwitch
                    v-model="settings.notifications.email.security_alerts"
                    label="Security Alerts"
                    color="primary"
                    hide-details
                    class="mb-2"
                  />
                  <VSwitch
                    v-model="settings.notifications.email.product_updates"
                    label="Product Updates"
                    color="primary"
                    hide-details
                    class="mb-2"
                  />
                  <VSwitch
                    v-model="settings.notifications.email.marketing"
                    label="Marketing & Promotional"
                    color="primary"
                    hide-details
                    class="mb-2"
                  />
                </div>

                <VDivider class="my-6" />

                <div class="mb-6">
                  <h3 class="text-h6 mb-4">Push Notifications</h3>
                  <VSwitch
                    v-model="settings.notifications.push.enabled"
                    label="Enable Push Notifications"
                    color="primary"
                    hide-details
                    class="mb-2"
                  />
                  <VSwitch
                    v-model="settings.notifications.push.sound"
                    label="Sound"
                    color="primary"
                    hide-details
                    class="mb-2"
                    :disabled="!settings.notifications.push.enabled"
                  />
                  <VSwitch
                    v-model="settings.notifications.push.vibration"
                    label="Vibration"
                    color="primary"
                    hide-details
                    class="mb-2"
                    :disabled="!settings.notifications.push.enabled"
                  />
                </div>

                <VBtn
                  color="primary"
                  @click="saveNotificationSettings"
                  :loading="savingSettings"
                >
                  Save Preferences
                </VBtn>
              </VCardText>
            </VCard>
          </VCol>
        </VRow>
      </VWindowItem>

      <!-- Appearance Settings -->
      <VWindowItem value="appearance">
        <VRow>
          <VCol cols="12" md="8">
            <VCard elevation="2" class="mb-6">
              <VCardTitle>Theme</VCardTitle>
              <VCardText>
                <VRadioGroup
                  v-model="settings.appearance.theme"
                  @update:model-value="updateTheme"
                >
                  <VRadio
                    label="Light Theme"
                    value="light"
                    color="primary"
                  />
                  <VRadio
                    label="Dark Theme"
                    value="dark"
                    color="primary"
                  />
                  <VRadio
                    label="System Default"
                    value="system"
                    color="primary"
                  />
                </VRadioGroup>
              </VCardText>
            </VCard>

            <VCard elevation="2" class="mb-6">
              <VCardTitle>Display</VCardTitle>
              <VCardText>
                <VSlider
                  v-model="settings.appearance.font_size"
                  label="Font Size"
                  min="12"
                  max="20"
                  step="1"
                  thumb-label
                  class="mb-4"
                  @update:model-value="updateFontSize"
                />
                
                <VSwitch
                  v-model="settings.appearance.compact_mode"
                  label="Compact Mode"
                  color="primary"
                  hide-details
                  class="mb-2"
                  @update:model-value="updateCompactMode"
                />
                
                <VSwitch
                  v-model="settings.appearance.animations"
                  label="Enable Animations"
                  color="primary"
                  hide-details
                  @update:model-value="updateAnimations"
                />
              </VCardText>
            </VCard>
          </VCol>
        </VRow>
      </VWindowItem>

      <!-- Privacy Settings -->
      <VWindowItem value="privacy">
        <VRow>
          <VCol cols="12" md="8">
            <VCard elevation="2" class="mb-6">
              <VCardTitle>Data & Privacy</VCardTitle>
              <VCardText>
                <VList>
                  <VListItem class="px-0">
                    <VListItemTitle>Data Export</VListItemTitle>
                    <VListItemSubtitle>
                      Download a copy of your data
                    </VListItemSubtitle>
                    <template #append>
                      <VBtn
                        variant="outlined"
                        size="small"
                        @click="exportData"
                      >
                        Export
                      </VBtn>
                    </template>
                  </VListItem>
                  
                  <VDivider class="my-4" />
                  
                  <VListItem class="px-0">
                    <VListItemTitle>Activity Tracking</VListItemTitle>
                    <VListItemSubtitle>
                      Allow us to track your activity for analytics
                    </VListItemSubtitle>
                    <template #append>
                      <VSwitch
                        v-model="settings.privacy.activity_tracking"
                        color="primary"
                        hide-details
                        @update:model-value="savePrivacySettings"
                      />
                    </template>
                  </VListItem>
                  
                  <VDivider class="my-4" />
                  
                  <VListItem class="px-0">
                    <VListItemTitle>Marketing Cookies</VListItemTitle>
                    <VListItemSubtitle>
                      Allow marketing and advertising cookies
                    </VListItemSubtitle>
                    <template #append>
                      <VSwitch
                        v-model="settings.privacy.marketing_cookies"
                        color="primary"
                        hide-details
                        @update:model-value="savePrivacySettings"
                      />
                    </template>
                  </VListItem>
                </VList>
              </VCardText>
            </VCard>
          </VCol>
        </VRow>
      </VWindowItem>

      <!-- Advanced Settings -->
      <VWindowItem value="advanced">
        <VRow>
          <VCol cols="12" md="8">
            <VCard elevation="2" class="mb-6">
              <VCardTitle>Developer Settings</VCardTitle>
              <VCardText>
                <VSwitch
                  v-model="settings.advanced.debug_mode"
                  label="Debug Mode"
                  color="primary"
                  hide-details
                  class="mb-2"
                  @update:model-value="saveAdvancedSettings"
                />
                
                <VSwitch
                  v-model="settings.advanced.api_logging"
                  label="API Request Logging"
                  color="primary"
                  hide-details
                  class="mb-2"
                  @update:model-value="saveAdvancedSettings"
                />
                
                <VSwitch
                  v-model="settings.advanced.performance_monitoring"
                  label="Performance Monitoring"
                  color="primary"
                  hide-details
                  @update:model-value="saveAdvancedSettings"
                />
              </VCardText>
            </VCard>

            <VCard elevation="2">
              <VCardTitle>Cache & Storage</VCardTitle>
              <VCardText>
                <VList>
                  <VListItem class="px-0">
                    <VListItemTitle>Clear Cache</VListItemTitle>
                    <VListItemSubtitle>
                      Clear application cache and temporary files
                    </VListItemSubtitle>
                    <template #append>
                      <VBtn
                        variant="outlined"
                        size="small"
                        @click="clearCache"
                      >
                        Clear
                      </VBtn>
                    </template>
                  </VListItem>
                  
                  <VDivider class="my-4" />
                  
                  <VListItem class="px-0">
                    <VListItemTitle>Reset Settings</VListItemTitle>
                    <VListItemSubtitle>
                      Reset all settings to default values
                    </VListItemSubtitle>
                    <template #append>
                      <VBtn
                        color="warning"
                        variant="outlined"
                        size="small"
                        @click="resetSettings"
                      >
                        Reset
                      </VBtn>
                    </template>
                  </VListItem>
                </VList>
              </VCardText>
            </VCard>
          </VCol>
        </VRow>
      </VWindowItem>
    </VWindow>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore, useUIStore } from '@/stores'

// Store references
const authStore = useAuthStore()
const uiStore = useUIStore()
const router = useRouter()

// Component state
const activeTab = ref('account')
const savingSettings = ref(false)

// Mock active sessions data
const activeSessions = ref([
  {
    id: '1',
    device_name: 'Chrome on Windows',
    device_icon: 'mdi-monitor',
    location: 'New York, NY',
    last_active: new Date(),
    is_current: true
  },
  {
    id: '2',
    device_name: 'Safari on iPhone',
    device_icon: 'mdi-cellphone',
    location: 'New York, NY',
    last_active: new Date(Date.now() - 1000 * 60 * 60 * 2), // 2 hours ago
    is_current: false
  }
])

// Settings data
const settings = reactive({
  notifications: {
    email: {
      account_activity: true,
      security_alerts: true,
      product_updates: false,
      marketing: false
    },
    push: {
      enabled: true,
      sound: true,
      vibration: false
    }
  },
  appearance: {
    theme: 'system',
    font_size: 14,
    compact_mode: false,
    animations: true
  },
  privacy: {
    activity_tracking: true,
    marketing_cookies: false
  },
  advanced: {
    debug_mode: false,
    api_logging: false,
    performance_monitoring: true
  }
})

// Computed properties
const user = computed(() => authStore.user)

// Methods

/**
 * Format date for display
 * 
 * @param dateString - ISO date string
 * @returns Formatted date string
 */
function formatDate(dateString?: string): string {
  if (!dateString) return 'Never'
  
  try {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    })
  } catch {
    return 'Invalid date'
  }
}

/**
 * Format date and time for display
 * 
 * @param dateString - ISO date string or Date object
 * @returns Formatted date and time string
 */
function formatDateTime(dateString?: string | Date): string {
  if (!dateString) return 'Never'
  
  try {
    const date = typeof dateString === 'string' ? new Date(dateString) : dateString
    const now = new Date()
    const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60))
    
    if (diffInMinutes < 1) return 'Just now'
    if (diffInMinutes < 60) return `${diffInMinutes} minutes ago`
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)} hours ago`
    
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  } catch {
    return 'Invalid date'
  }
}

/**
 * Delete user account
 */
async function deleteAccount() {
  const confirmed = await uiStore.confirm(
    'Delete Account',
    'Are you absolutely sure you want to delete your account? This action cannot be undone and you will lose all your data.',
    {
      confirmText: 'Delete Account',
      confirmColor: 'error'
    }
  )

  if (confirmed) {
    try {
      // In a real app, this would call an API to delete the account
      uiStore.showInfo('Account deletion would be processed here.')
    } catch (error: any) {
      console.error('Failed to delete account:', error)
      uiStore.showError('Failed to delete account. Please try again.')
    }
  }
}

/**
 * Change password
 */
function changePassword() {
  router.push({ name: 'change-password' })
}

/**
 * Enable two-factor authentication
 */
function enable2FA() {
  uiStore.showInfo('Two-factor authentication setup will be implemented.')
}

/**
 * Disable two-factor authentication
 */
async function disable2FA() {
  const confirmed = await uiStore.confirm(
    'Disable 2FA',
    'Are you sure you want to disable two-factor authentication? This will make your account less secure.',
    {
      confirmText: 'Disable 2FA',
      confirmColor: 'warning'
    }
  )

  if (confirmed) {
    uiStore.showInfo('Two-factor authentication would be disabled here.')
  }
}

/**
 * Terminate a session
 * 
 * @param sessionId - Session ID to terminate
 */
async function terminateSession(sessionId: string) {
  try {
    // In a real app, this would call an API to terminate the session
    activeSessions.value = activeSessions.value.filter(s => s.id !== sessionId)
    uiStore.showSuccess('Session terminated successfully.')
  } catch (error: any) {
    console.error('Failed to terminate session:', error)
    uiStore.showError('Failed to terminate session.')
  }
}

/**
 * Logout all sessions
 */
async function logoutAllSessions() {
  const confirmed = await uiStore.confirm(
    'Logout All Sessions',
    'This will log you out from all devices and sessions. You will need to sign in again. Continue?',
    {
      confirmText: 'Logout All',
      confirmColor: 'warning'
    }
  )

  if (confirmed) {
    try {
      await authStore.logout()
      uiStore.showSuccess('Successfully logged out from all sessions.')
      router.push({ name: 'login' })
    } catch (error: any) {
      console.error('Failed to logout all sessions:', error)
      uiStore.showError('Failed to logout all sessions.')
    }
  }
}

/**
 * Save notification settings
 */
async function saveNotificationSettings() {
  try {
    savingSettings.value = true
    // In a real app, this would call an API to save settings
    await new Promise(resolve => setTimeout(resolve, 1000)) // Simulate API call
    uiStore.showSuccess('Notification preferences saved.')
  } catch (error: any) {
    console.error('Failed to save notification settings:', error)
    uiStore.showError('Failed to save notification preferences.')
  } finally {
    savingSettings.value = false
  }
}

/**
 * Update theme setting
 * 
 * @param theme - Theme value
 */
function updateTheme(theme: string) {
  uiStore.setTheme(theme as 'light' | 'dark' | 'system')
  uiStore.showSuccess('Theme updated.')
}

/**
 * Update font size
 * 
 * @param fontSize - Font size value
 */
function updateFontSize(fontSize: number) {
  // In a real app, this would update CSS custom properties
  document.documentElement.style.setProperty('--app-font-size', `${fontSize}px`)
  uiStore.showSuccess('Font size updated.')
}

/**
 * Update compact mode
 * 
 * @param compact - Compact mode value
 */
function updateCompactMode(compact: boolean) {
  // In a real app, this would update layout classes
  document.body.classList.toggle('compact-mode', compact)
  uiStore.showSuccess(`Compact mode ${compact ? 'enabled' : 'disabled'}.`)
}

/**
 * Update animations
 * 
 * @param animations - Animations value
 */
function updateAnimations(animations: boolean) {
  // In a real app, this would update animation classes
  document.body.classList.toggle('no-animations', !animations)
  uiStore.showSuccess(`Animations ${animations ? 'enabled' : 'disabled'}.`)
}

/**
 * Save privacy settings
 */
async function savePrivacySettings() {
  try {
    // In a real app, this would call an API to save settings
    uiStore.showSuccess('Privacy settings saved.')
  } catch (error: any) {
    console.error('Failed to save privacy settings:', error)
    uiStore.showError('Failed to save privacy settings.')
  }
}

/**
 * Save advanced settings
 */
async function saveAdvancedSettings() {
  try {
    // In a real app, this would call an API to save settings
    uiStore.showSuccess('Advanced settings saved.')
  } catch (error: any) {
    console.error('Failed to save advanced settings:', error)
    uiStore.showError('Failed to save advanced settings.')
  }
}

/**
 * Export user data
 */
function exportData() {
  uiStore.showInfo('Data export functionality will be implemented.')
}

/**
 * Clear application cache
 */
async function clearCache() {
  const confirmed = await uiStore.confirm(
    'Clear Cache',
    'This will clear all cached data and you may need to reload some content. Continue?'
  )

  if (confirmed) {
    try {
      // Clear various caches
      if ('caches' in window) {
        const cacheNames = await caches.keys()
        await Promise.all(cacheNames.map(name => caches.delete(name)))
      }
      
      localStorage.removeItem('app-cache')
      sessionStorage.clear()
      
      uiStore.showSuccess('Cache cleared successfully.')
    } catch (error: any) {
      console.error('Failed to clear cache:', error)
      uiStore.showError('Failed to clear cache.')
    }
  }
}

/**
 * Reset all settings to defaults
 */
async function resetSettings() {
  const confirmed = await uiStore.confirm(
    'Reset Settings',
    'This will reset all your preferences to default values. This action cannot be undone. Continue?',
    {
      confirmText: 'Reset Settings',
      confirmColor: 'warning'
    }
  )

  if (confirmed) {
    try {
      // Reset settings to defaults
      Object.assign(settings, {
        notifications: {
          email: {
            account_activity: true,
            security_alerts: true,
            product_updates: false,
            marketing: false
          },
          push: {
            enabled: true,
            sound: true,
            vibration: false
          }
        },
        appearance: {
          theme: 'system',
          font_size: 14,
          compact_mode: false,
          animations: true
        },
        privacy: {
          activity_tracking: true,
          marketing_cookies: false
        },
        advanced: {
          debug_mode: false,
          api_logging: false,
          performance_monitoring: true
        }
      })

      // Apply theme reset
      uiStore.setTheme('system')
      
      uiStore.showSuccess('Settings reset to defaults.')
    } catch (error: any) {
      console.error('Failed to reset settings:', error)
      uiStore.showError('Failed to reset settings.')
    }
  }
}

// Lifecycle hooks
onMounted(() => {
  // Load current settings from storage or API
  const savedSettings = localStorage.getItem('app-settings')
  if (savedSettings) {
    try {
      Object.assign(settings, JSON.parse(savedSettings))
    } catch (error) {
      console.error('Failed to load saved settings:', error)
    }
  }
})
</script>

<style scoped>
.settings-view {
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px;
}

.v-card {
  border-radius: 16px;
}

.v-card-title {
  padding-bottom: 8px;
  font-weight: 600;
}

.v-tab {
  text-transform: none;
  font-weight: 500;
}

.v-window-item {
  padding-top: 16px;
}

.v-list-item {
  min-height: 64px;
  padding: 12px 0;
}

.v-list-item-title {
  font-weight: 500;
  margin-bottom: 4px;
}

.v-list-item-subtitle {
  opacity: 0.7;
  line-height: 1.4;
}

.v-switch {
  margin-bottom: 0;
}

.v-switch :deep(.v-selection-control__wrapper) {
  margin-right: 16px;
}

.v-radio-group :deep(.v-selection-control) {
  margin-bottom: 8px;
}

.v-slider {
  margin-top: 16px;
}

/* Button styling */
.v-btn {
  border-radius: 12px;
  text-transform: none;
  font-weight: 500;
}

/* Card hover effects */
.v-card {
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.v-card:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
}

/* Alert styling */
.v-alert {
  border-radius: 12px;
}

/* Responsive adjustments */
@media (max-width: 960px) {
  .settings-view {
    padding: 16px;
  }
  
  .v-tabs {
    margin-bottom: 20px;
  }
}

@media (max-width: 600px) {
  .v-card-text {
    padding: 16px;
  }
  
  .v-list-item {
    flex-direction: column;
    align-items: stretch;
    min-height: auto;
  }
  
  .v-list-item__append {
    margin-top: 8px;
    align-self: flex-start;
  }
}
</style>
