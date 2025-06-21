/**
 * Dashboard View Component
 * 
 * Main dashboard page displaying overview information, statistics,
 * and quick actions for authenticated users.
 */

<template>
  <div class="dashboard-view">
    <!-- Page Header -->
    <div class="d-flex justify-space-between align-center mb-6">
      <div>
        <h1 class="text-h4 font-weight-bold mb-2">
          Welcome back, {{ authStore.user?.first_name }}!
        </h1>
        <p class="text-subtitle-1 text-medium-emphasis">
          Here's what's happening with your account today.
        </p>
      </div>
      
      <!-- Quick Actions -->
      <div class="d-flex gap-2">
        <VBtn
          color="primary"
          prepend-icon="mdi-plus"
          @click="showCreateDialog"
        >
          New Item
        </VBtn>
        
        <VBtn
          variant="outlined"
          prepend-icon="mdi-refresh"
          @click="refreshData"
          :loading="isRefreshing"
        >
          Refresh
        </VBtn>
      </div>
    </div>

    <!-- Statistics Cards -->
    <VRow class="mb-6">
      <VCol
        v-for="stat in statistics"
        :key="stat.title"
        cols="12"
        sm="6"
        md="3"
      >
        <VCard>
          <VCardText>
            <div class="d-flex justify-space-between align-center">
              <div>
                <p class="text-caption text-medium-emphasis mb-1">
                  {{ stat.title }}
                </p>
                <p class="text-h5 font-weight-bold">
                  {{ stat.value }}
                </p>
                <p 
                  class="text-caption"
                  :class="stat.changeColor"
                >
                  {{ stat.change }}
                </p>
              </div>
              
              <VAvatar
                :color="stat.color"
                size="48"
                variant="tonal"
              >
                <VIcon :icon="stat.icon" />
              </VAvatar>
            </div>
          </VCardText>
        </VCard>
      </VCol>
    </VRow>

    <!-- Main Content Grid -->
    <VRow>
      <!-- Recent Activity -->
      <VCol cols="12" md="8">
        <VCard>
          <VCardTitle class="d-flex justify-space-between align-center">
            <span>Recent Activity</span>
            <VBtn
              variant="text"
              size="small"
              @click="viewAllActivity"
            >
              View All
            </VBtn>
          </VCardTitle>
          
          <VCardText>
            <VList>
              <VListItem
                v-for="activity in recentActivity"
                :key="activity.id"
                :prepend-icon="activity.icon"
              >
                <VListItemTitle>{{ activity.title }}</VListItemTitle>
                <VListItemSubtitle>{{ activity.description }}</VListItemSubtitle>
                
                <template #append>
                  <VListItemAction>
                    <span class="text-caption text-medium-emphasis">
                      {{ formatRelativeTime(activity.timestamp) }}
                    </span>
                  </VListItemAction>
                </template>
              </VListItem>
              
              <VListItem v-if="recentActivity.length === 0">
                <VListItemTitle class="text-center text-medium-emphasis">
                  No recent activity
                </VListItemTitle>
              </VListItem>
            </VList>
          </VCardText>
        </VCard>
      </VCol>

      <!-- Quick Stats & Profile -->
      <VCol cols="12" md="4">
        <!-- Profile Summary -->
        <VCard class="mb-4">
          <VCardTitle>Profile Summary</VCardTitle>
          <VCardText>
            <div class="d-flex align-center mb-4">
              <VAvatar
                :color="authStore.user?.is_email_verified ? 'success' : 'warning'"
                size="64"
                class="mr-4"
              >
                <span class="text-h6 font-weight-bold">
                  {{ authStore.userInitials }}
                </span>
              </VAvatar>
              
              <div>
                <p class="text-subtitle-1 font-weight-medium">
                  {{ authStore.userFullName }}
                </p>
                <p class="text-caption text-medium-emphasis">
                  {{ authStore.user?.email }}
                </p>
                <VChip
                  :color="authStore.user?.is_email_verified ? 'success' : 'warning'"
                  size="small"
                  variant="tonal"
                  class="mt-1"
                >
                  {{ authStore.user?.is_email_verified ? 'Verified' : 'Unverified' }}
                </VChip>
              </div>
            </div>
            
            <VBtn
              :to="{ name: 'edit-profile' }"
              color="primary"
              variant="outlined"
              block
            >
              Edit Profile
            </VBtn>
          </VCardText>
        </VCard>

        <!-- Quick Actions -->
        <VCard>
          <VCardTitle>Quick Actions</VCardTitle>
          <VCardText>
            <VList>
              <VListItem
                prepend-icon="mdi-account-edit"
                title="Update Profile"
                subtitle="Change your personal information"
                @click="goToProfile"
              />
              
              <VListItem
                prepend-icon="mdi-cog"
                title="Settings"
                subtitle="Configure your preferences"
                @click="goToSettings"
              />
              
              <VListItem
                prepend-icon="mdi-help-circle"
                title="Help & Support"
                subtitle="Get help and documentation"
                @click="showHelp"
              />
            </VList>
          </VCardText>
        </VCard>
      </VCol>
    </VRow>
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

// Local state
const isRefreshing = ref(false)

// Mock data for demonstration
const statistics = computed(() => [
  {
    title: 'Total Items',
    value: '24',
    change: '+12% from last month',
    changeColor: 'text-success',
    icon: 'mdi-file-document',
    color: 'primary'
  },
  {
    title: 'Active Projects',
    value: '3',
    change: '+2 this week',
    changeColor: 'text-success',
    icon: 'mdi-briefcase',
    color: 'success'
  },
  {
    title: 'Completed Tasks',
    value: '18',
    change: '+5 today',
    changeColor: 'text-success',
    icon: 'mdi-check-circle',
    color: 'info'
  },
  {
    title: 'Pending Reviews',
    value: '2',
    change: '-1 from yesterday',
    changeColor: 'text-warning',
    icon: 'mdi-clock-outline',
    color: 'warning'
  }
])

const recentActivity = ref([
  {
    id: 1,
    title: 'Profile updated',
    description: 'You updated your profile information',
    icon: 'mdi-account-edit',
    timestamp: Date.now() - 3600000 // 1 hour ago
  },
  {
    id: 2,
    title: 'New project created',
    description: 'Created "Website Redesign" project',
    icon: 'mdi-plus-circle',
    timestamp: Date.now() - 7200000 // 2 hours ago
  },
  {
    id: 3,
    title: 'Task completed',
    description: 'Completed "Database Migration" task',
    icon: 'mdi-check-circle',
    timestamp: Date.now() - 86400000 // 1 day ago
  }
])

// Methods

/**
 * Show create new item dialog
 */
function showCreateDialog() {
  uiStore.showInfo('Create new item functionality will be implemented here.')
}

/**
 * Refresh dashboard data
 */
async function refreshData() {
  try {
    isRefreshing.value = true
    
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000))
    
    // Refresh user data
    await authStore.fetchCurrentUser()
    
    uiStore.showSuccess('Dashboard data refreshed successfully')
  } catch (error) {
    console.error('Failed to refresh data:', error)
    uiStore.showError('Failed to refresh dashboard data')
  } finally {
    isRefreshing.value = false
  }
}

/**
 * Navigate to profile page
 */
function goToProfile() {
  router.push({ name: 'profile' })
}

/**
 * Navigate to settings page
 */
function goToSettings() {
  router.push({ name: 'settings' })
}

/**
 * View all activity
 */
function viewAllActivity() {
  uiStore.showInfo('Activity history page will be implemented here.')
}

/**
 * Show help information
 */
function showHelp() {
  uiStore.showInfo(
    'Welcome to your dashboard! Here you can view your account overview, recent activity, and quick actions.',
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

/**
 * Format relative time
 * 
 * @param timestamp - Unix timestamp
 * @returns Formatted relative time string
 */
function formatRelativeTime(timestamp: number): string {
  const now = Date.now()
  const diff = now - timestamp
  
  if (diff < 60000) {
    return 'Just now'
  } else if (diff < 3600000) {
    const minutes = Math.floor(diff / 60000)
    return `${minutes}m ago`
  } else if (diff < 86400000) {
    const hours = Math.floor(diff / 3600000)
    return `${hours}h ago`
  } else {
    const days = Math.floor(diff / 86400000)
    return `${days}d ago`
  }
}

// Lifecycle
onMounted(() => {
  // Load dashboard data
  refreshData()
})
</script>

<style scoped>
.dashboard-view {
  padding: 24px;
  max-width: 1400px;
  margin: 0 auto;
}

.v-card {
  transition: all 0.3s ease;
}

.v-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.v-list-item {
  cursor: pointer;
  border-radius: 8px;
  margin: 4px 0;
}

.v-list-item:hover {
  background-color: rgba(var(--v-theme-primary), 0.1);
}

/* Responsive adjustments */
@media (max-width: 960px) {
  .dashboard-view {
    padding: 16px;
  }
  
  .d-flex.justify-space-between {
    flex-direction: column;
    align-items: flex-start;
    gap: 16px;
  }
  
  .d-flex.gap-2 {
    width: 100%;
    justify-content: space-between;
  }
}

@media (max-width: 600px) {
  .dashboard-view {
    padding: 12px;
  }
  
  .text-h4 {
    font-size: 1.5rem !important;
  }
  
  .v-btn {
    font-size: 0.875rem;
  }
}
</style>
