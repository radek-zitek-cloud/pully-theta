/**
 * Profile View Component
 * 
 * Displays user profile information with edit functionality and settings.
 * Provides a comprehensive overview of user data and account status.
 */

<template>
  <div class="profile-view">
    <!-- Header Section -->
    <VCard class="mb-6" elevation="2">
      <VCardText class="pa-6">
        <div class="d-flex align-center">
          <VAvatar
            :image="user?.avatar_url"
            size="80"
            color="primary"
            class="mr-4"
          >
            <VIcon v-if="!user?.avatar_url" size="40">
              mdi-account
            </VIcon>
          </VAvatar>
          
          <div class="flex-grow-1">
            <h1 class="text-h4 font-weight-bold mb-1">
              {{ fullName }}
            </h1>
            <p class="text-body-1 text-medium-emphasis mb-2">
              {{ user?.email }}
            </p>
            <div class="d-flex align-center">
              <VChip
                :color="statusColor"
                size="small"
                variant="tonal"
                class="mr-2"
              >
                <VIcon start size="small">
                  {{ statusIcon }}
                </VIcon>
                {{ statusText }}
              </VChip>
              <VChip
                color="info"
                size="small"
                variant="tonal"
                v-if="user?.role"
              >
                {{ user.role }}
              </VChip>
            </div>
          </div>
          
          <div class="d-flex flex-column gap-2">
            <VBtn
              :to="{ name: 'edit-profile' }"
              color="primary"
              variant="elevated"
              prepend-icon="mdi-pencil"
            >
              Edit Profile
            </VBtn>
            <VBtn
              :to="{ name: 'settings' }"
              variant="outlined"
              prepend-icon="mdi-cog"
            >
              Settings
            </VBtn>
          </div>
        </div>
      </VCardText>
    </VCard>

    <!-- Profile Information Tabs -->
    <VTabs
      v-model="activeTab"
      class="mb-4"
      color="primary"
    >
      <VTab value="overview">
        <VIcon start>mdi-account-circle</VIcon>
        Overview
      </VTab>
      <VTab value="activity">
        <VIcon start>mdi-timeline</VIcon>
        Activity
      </VTab>
      <VTab value="security">
        <VIcon start>mdi-shield-check</VIcon>
        Security
      </VTab>
    </VTabs>

    <VWindow v-model="activeTab">
      <!-- Overview Tab -->
      <VWindowItem value="overview">
        <VRow>
          <!-- Personal Information -->
          <VCol cols="12" md="6">
            <VCard elevation="2">
              <VCardTitle class="d-flex align-center">
                <VIcon class="mr-2">mdi-account-details</VIcon>
                Personal Information
              </VCardTitle>
              <VCardText>
                <VList>
                  <VListItem>
                    <VListItemTitle>Full Name</VListItemTitle>
                    <VListItemSubtitle>{{ fullName }}</VListItemSubtitle>
                  </VListItem>
                  <VListItem>
                    <VListItemTitle>Email</VListItemTitle>
                    <VListItemSubtitle>{{ user?.email }}</VListItemSubtitle>
                  </VListItem>
                  <VListItem v-if="user?.phone">
                    <VListItemTitle>Phone</VListItemTitle>
                    <VListItemSubtitle>{{ user.phone }}</VListItemSubtitle>
                  </VListItem>
                  <VListItem v-if="user?.department">
                    <VListItemTitle>Department</VListItemTitle>
                    <VListItemSubtitle>{{ user.department }}</VListItemSubtitle>
                  </VListItem>
                  <VListItem>
                    <VListItemTitle>Member Since</VListItemTitle>
                    <VListItemSubtitle>{{ formatDate(user?.created_at) }}</VListItemSubtitle>
                  </VListItem>
                </VList>
              </VCardText>
            </VCard>
          </VCol>

          <!-- Account Status -->
          <VCol cols="12" md="6">
            <VCard elevation="2">
              <VCardTitle class="d-flex align-center">
                <VIcon class="mr-2">mdi-information</VIcon>
                Account Status
              </VCardTitle>
              <VCardText>
                <VList>
                  <VListItem>
                    <VListItemTitle>Status</VListItemTitle>
                    <VListItemSubtitle>
                      <VChip
                        :color="statusColor"
                        size="small"
                        variant="tonal"
                      >
                        {{ statusText }}
                      </VChip>
                    </VListItemSubtitle>
                  </VListItem>
                  <VListItem>
                    <VListItemTitle>Role</VListItemTitle>
                    <VListItemSubtitle>{{ user?.role || 'User' }}</VListItemSubtitle>
                  </VListItem>
                  <VListItem>
                    <VListItemTitle>Email Verified</VListItemTitle>
                    <VListItemSubtitle>
                      <VIcon
                        :color="user?.is_email_verified ? 'success' : 'warning'"
                        size="small"
                      >
                        {{ user?.is_email_verified ? 'mdi-check-circle' : 'mdi-alert-circle' }}
                      </VIcon>
                      {{ user?.is_email_verified ? 'Verified' : 'Not Verified' }}
                    </VListItemSubtitle>
                  </VListItem>
                  <VListItem>
                    <VListItemTitle>Last Login</VListItemTitle>
                    <VListItemSubtitle>{{ formatDateTime(user?.last_login_at) }}</VListItemSubtitle>
                  </VListItem>
                </VList>
              </VCardText>
            </VCard>
          </VCol>
        </VRow>
      </VWindowItem>

      <!-- Activity Tab -->
      <VWindowItem value="activity">
        <VCard elevation="2">
          <VCardTitle class="d-flex align-center">
            <VIcon class="mr-2">mdi-history</VIcon>
            Recent Activity
          </VCardTitle>
          <VCardText>
            <VList v-if="activityData.length">
              <VListItem
                v-for="(activity, index) in activityData"
                :key="index"
                class="px-0"
              >
                <template #prepend>
                  <VAvatar
                    :color="activity.color"
                    size="small"
                    variant="tonal"
                  >
                    <VIcon size="small">{{ activity.icon }}</VIcon>
                  </VAvatar>
                </template>
                <VListItemTitle>{{ activity.title }}</VListItemTitle>
                <VListItemSubtitle>{{ activity.description }}</VListItemSubtitle>
                <template #append>
                  <span class="text-caption text-medium-emphasis">
                    {{ formatDateTime(activity.timestamp) }}
                  </span>
                </template>
              </VListItem>
            </VList>
            <div v-else class="text-center py-8">
              <VIcon size="64" color="grey-lighten-2">mdi-timeline-outline</VIcon>
              <p class="text-body-1 text-medium-emphasis mt-4">
                No recent activity to display
              </p>
            </div>
          </VCardText>
        </VCard>
      </VWindowItem>

      <!-- Security Tab -->
      <VWindowItem value="security">
        <VRow>
          <!-- Password Security -->
          <VCol cols="12" md="6">
            <VCard elevation="2">
              <VCardTitle class="d-flex align-center">
                <VIcon class="mr-2">mdi-lock</VIcon>
                Password Security
              </VCardTitle>
              <VCardText>
                <VList>
                  <VListItem>
                    <VListItemTitle>Password Last Changed</VListItemTitle>
                    <VListItemSubtitle>{{ formatDate(user?.password_changed_at) }}</VListItemSubtitle>
                  </VListItem>
                  <VListItem>
                    <VListItemTitle>Password Strength</VListItemTitle>
                    <VListItemSubtitle>
                      <VChip color="success" size="small" variant="tonal">
                        Strong
                      </VChip>
                    </VListItemSubtitle>
                  </VListItem>
                </VList>
                <VBtn
                  color="primary"
                  variant="outlined"
                  prepend-icon="mdi-key-change"
                  class="mt-4"
                  @click="changePassword"
                >
                  Change Password
                </VBtn>
              </VCardText>
            </VCard>
          </VCol>

          <!-- Security Settings -->
          <VCol cols="12" md="6">
            <VCard elevation="2">
              <VCardTitle class="d-flex align-center">
                <VIcon class="mr-2">mdi-shield-check</VIcon>
                Security Settings
              </VCardTitle>
              <VCardText>
                <VList>
                  <VListItem>
                    <VListItemTitle>Two-Factor Authentication</VListItemTitle>
                    <VListItemSubtitle>
                      <VChip
                        :color="user?.two_factor_enabled ? 'success' : 'warning'"
                        size="small"
                        variant="tonal"
                      >
                        {{ user?.two_factor_enabled ? 'Enabled' : 'Disabled' }}
                      </VChip>
                    </VListItemSubtitle>
                  </VListItem>
                  <VListItem>
                    <VListItemTitle>Active Sessions</VListItemTitle>
                    <VListItemSubtitle>{{ activeSessions }} session(s)</VListItemSubtitle>
                  </VListItem>
                </VList>
                <div class="d-flex gap-2 mt-4">
                  <VBtn
                    v-if="!user?.two_factor_enabled"
                    color="success"
                    variant="outlined"
                    prepend-icon="mdi-shield-plus"
                    @click="enable2FA"
                  >
                    Enable 2FA
                  </VBtn>
                  <VBtn
                    color="warning"
                    variant="outlined"
                    prepend-icon="mdi-logout-variant"
                    @click="logoutAllSessions"
                  >
                    Logout All Sessions
                  </VBtn>
                </div>
              </VCardText>
            </VCard>
          </VCol>
        </VRow>
      </VWindowItem>
    </VWindow>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore, useUIStore } from '@/stores'

// Store references
const authStore = useAuthStore()
const uiStore = useUIStore()
const router = useRouter()

// Component state
const activeTab = ref('overview')
const activeSessions = ref(1) // Mock data - would come from API

// Mock activity data - in real app, this would come from an API
const activityData = ref([
  {
    title: 'Profile Updated',
    description: 'You updated your profile information',
    timestamp: new Date(Date.now() - 1000 * 60 * 30), // 30 minutes ago
    icon: 'mdi-account-edit',
    color: 'info'
  },
  {
    title: 'Password Changed',
    description: 'Your password was successfully changed',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7), // 1 week ago
    icon: 'mdi-key-change',
    color: 'success'
  },
  {
    title: 'Login from New Device',
    description: 'Successful login from Chrome on Windows',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 14), // 2 weeks ago
    icon: 'mdi-login',
    color: 'warning'
  }
])

// Computed properties
const user = computed(() => authStore.user)

const fullName = computed(() => {
  if (!user.value) return 'Unknown User'
  return `${user.value.first_name} ${user.value.last_name}`.trim()
})

const statusColor = computed(() => {
  if (!user.value) return 'grey'
  
  switch (user.value.status) {
    case 'active':
      return 'success'
    case 'inactive':
      return 'warning'
    case 'suspended':
      return 'error'
    default:
      return 'grey'
  }
})

const statusIcon = computed(() => {
  if (!user.value) return 'mdi-help-circle'
  
  switch (user.value.status) {
    case 'active':
      return 'mdi-check-circle'
    case 'inactive':
      return 'mdi-pause-circle'
    case 'suspended':
      return 'mdi-cancel'
    default:
      return 'mdi-help-circle'
  }
})

const statusText = computed(() => {
  if (!user.value) return 'Unknown'
  
  switch (user.value.status) {
    case 'active':
      return 'Active'
    case 'inactive':
      return 'Inactive'
    case 'suspended':
      return 'Suspended'
    default:
      return 'Unknown'
  }
})

// Methods

/**
 * Format date for display
 * 
 * @param dateString - ISO date string
 * @returns Formatted date string
 */
function formatDate(dateString?: string): string {
  if (!dateString) return 'Not available'
  
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
  if (!dateString) return 'Not available'
  
  try {
    const date = typeof dateString === 'string' ? new Date(dateString) : dateString
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
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
 * Handle password change action
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
 * Logout all active sessions
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
      // In a real app, this would call an API to invalidate all sessions
      await authStore.logout()
      uiStore.showSuccess('Successfully logged out from all sessions.')
      router.push({ name: 'login' })
    } catch (error: any) {
      console.error('Failed to logout all sessions:', error)
      uiStore.showError('Failed to logout all sessions. Please try again.')
    }
  }
}

/**
 * Load user profile data
 */
async function loadProfile() {
  try {
    await authStore.fetchCurrentUser()
  } catch (error: any) {
    console.error('Failed to load profile:', error)
    uiStore.showError('Failed to load profile data.')
  }
}

// Lifecycle hooks
onMounted(() => {
  if (!user.value) {
    loadProfile()
  }
})
</script>

<style scoped>
.profile-view {
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px;
}

.v-card {
  border-radius: 16px;
}

.v-card-title {
  padding-bottom: 8px;
}

.v-list-item {
  min-height: 56px;
}

.v-list-item-title {
  font-weight: 500;
  margin-bottom: 4px;
}

.v-list-item-subtitle {
  opacity: 0.7;
}

.v-tab {
  text-transform: none;
  font-weight: 500;
}

.v-window-item {
  padding-top: 16px;
}

/* Avatar hover effect */
.v-avatar {
  transition: transform 0.2s ease;
}

.v-avatar:hover {
  transform: scale(1.05);
}

/* Card hover effects */
.v-card {
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.v-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12);
}

/* Button styling */
.v-btn {
  border-radius: 12px;
  text-transform: none;
  font-weight: 500;
}

/* Responsive adjustments */
@media (max-width: 960px) {
  .profile-view {
    padding: 16px;
  }
  
  .d-flex {
    flex-direction: column;
    align-items: stretch !important;
  }
  
  .v-avatar {
    align-self: center;
    margin-bottom: 16px;
    margin-right: 0 !important;
  }
  
  .d-flex.flex-column.gap-2 {
    flex-direction: row;
    gap: 8px;
  }
}

@media (max-width: 600px) {
  .v-card-text {
    padding: 16px;
  }
  
  .d-flex.flex-column.gap-2 {
    flex-direction: column;
  }
}
</style>
