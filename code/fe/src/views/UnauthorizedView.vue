/**
 * Unauthorized (403) View Component
 * 
 * Displays when users try to access resources they don't have permission for.
 * Provides clear messaging and options for users to resolve the access issue.
 */

<template>
  <div class="unauthorized-view">
    <VContainer class="fill-height">
      <VRow 
        justify="center" 
        align="center"
        class="text-center"
      >
        <VCol cols="12" md="8" lg="6">
          <!-- Error Illustration -->
          <div class="error-illustration mb-8">
            <VIcon 
              size="120" 
              color="warning" 
              class="mb-4"
            >
              mdi-shield-lock-outline
            </VIcon>
            
            <div class="error-code">
              <span class="text-h1 font-weight-bold text-warning">4</span>
              <VIcon 
                size="80" 
                color="warning" 
                class="mx-2"
              >
                mdi-lock
              </VIcon>
              <span class="text-h1 font-weight-bold text-warning">3</span>
            </div>
          </div>

          <!-- Error Message -->
          <div class="error-message mb-8">
            <h1 class="text-h3 font-weight-bold mb-4">
              Access Denied
            </h1>
            <p class="text-h6 text-medium-emphasis mb-6">
              You don't have permission to access this resource.
            </p>
            <p class="text-body-1 text-medium-emphasis">
              This could be because:
            </p>
          </div>

          <!-- Reasons List -->
          <VCard 
            variant="tonal" 
            color="warning"
            class="mx-auto mb-8"
            max-width="500"
          >
            <VCardText>
              <VList bg-color="transparent">
                <VListItem
                  prepend-icon="mdi-account-remove"
                >
                  <VListItemTitle>Insufficient Permissions</VListItemTitle>
                  <VListItemSubtitle>
                    Your account doesn't have the required permissions
                  </VListItemSubtitle>
                </VListItem>
                
                <VListItem
                  prepend-icon="mdi-clock-outline"
                >
                  <VListItemTitle>Session Expired</VListItemTitle>
                  <VListItemSubtitle>
                    Your login session may have expired
                  </VListItemSubtitle>
                </VListItem>
                
                <VListItem
                  prepend-icon="mdi-account-lock"
                >
                  <VListItemTitle>Account Restrictions</VListItemTitle>
                  <VListItemSubtitle>
                    Your account may have restrictions applied
                  </VListItemSubtitle>
                </VListItem>
              </VList>
            </VCardText>
          </VCard>

          <!-- Action Buttons -->
          <div class="action-buttons mb-8">
            <VBtn
              @click="signInWithDifferentAccount"
              color="primary"
              size="large"
              variant="elevated"
              prepend-icon="mdi-account-switch"
              class="mr-4 mb-2"
            >
              Sign In Different Account
            </VBtn>
            
            <VBtn
              :to="{ name: 'dashboard' }"
              variant="outlined"
              size="large"
              prepend-icon="mdi-home"
              class="mr-4 mb-2"
            >
              Go Home
            </VBtn>
            
            <VBtn
              @click="refreshPage"
              variant="text"
              size="large"
              prepend-icon="mdi-refresh"
              class="mb-2"
            >
              Refresh
            </VBtn>
          </div>

          <!-- Current User Info -->
          <VCard 
            v-if="user"
            variant="outlined"
            class="mx-auto mb-6"
            max-width="400"
          >
            <VCardTitle class="text-center">
              <VIcon class="mr-2">mdi-account-circle</VIcon>
              Current User
            </VCardTitle>
            <VCardText class="text-center">
              <VAvatar
                size="60"
                :image="user.avatar_url"
                color="primary"
                class="mb-4"
              >
                <VIcon v-if="!user.avatar_url" size="30">
                  mdi-account
                </VIcon>
              </VAvatar>
              
              <div>
                <p class="text-body-1 font-weight-medium">
                  {{ fullName }}
                </p>
                <p class="text-body-2 text-medium-emphasis">
                  {{ user.email }}
                </p>
                <VChip
                  :color="roleColor"
                  size="small"
                  variant="tonal"
                  class="mt-2"
                >
                  {{ user.role || 'User' }}
                </VChip>
              </div>
            </VCardText>
          </VCard>

          <!-- Request Access -->
          <VCard 
            variant="outlined"
            class="mx-auto"
            max-width="500"
          >
            <VCardTitle class="text-center">
              <VIcon class="mr-2">mdi-help-circle</VIcon>
              Need Access?
            </VCardTitle>
            <VCardText class="text-center">
              <p class="text-body-2 text-medium-emphasis mb-4">
                If you believe you should have access to this resource, 
                you can request permission from your administrator.
              </p>
              
              <div class="d-flex justify-center gap-2">
                <VBtn
                  @click="requestAccess"
                  color="success"
                  variant="outlined"
                  prepend-icon="mdi-account-plus"
                >
                  Request Access
                </VBtn>
                
                <VBtn
                  @click="contactSupport"
                  variant="text"
                  prepend-icon="mdi-help-circle"
                >
                  Contact Support
                </VBtn>
              </div>
            </VCardText>
          </VCard>
        </VCol>
      </VRow>
    </VContainer>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore, useUIStore } from '@/stores'

// Store references
const authStore = useAuthStore()
const uiStore = useUIStore()
const router = useRouter()
const route = useRoute()

// Computed properties
const user = computed(() => authStore.user)

const fullName = computed(() => {
  if (!user.value) return 'Unknown User'
  return `${user.value.first_name} ${user.value.last_name}`.trim()
})

const roleColor = computed(() => {
  if (!user.value?.role) return 'grey'
  
  const roleColors: Record<string, string> = {
    'admin': 'error',
    'manager': 'warning',
    'user': 'info',
    'guest': 'grey'
  }
  
  return roleColors[user.value.role.toLowerCase()] || 'info'
})

// Methods

/**
 * Sign in with a different account
 */
function signInWithDifferentAccount() {
  // Clear current session and redirect to login
  authStore.logout().then(() => {
    router.push({ 
      name: 'login',
      query: { 
        redirect: route.fullPath,
        reason: 'unauthorized'
      }
    })
  })
}

/**
 * Refresh the current page
 */
function refreshPage() {
  window.location.reload()
}

/**
 * Request access to the resource
 */
async function requestAccess() {
  const confirmed = await uiStore.confirm(
    'Request Access',
    `Do you want to request access to "${route.path}"? Your administrator will be notified.`,
    {
      confirmText: 'Send Request',
      confirmColor: 'success'
    }
  )

  if (confirmed) {
    try {
      // In a real app, this would send an access request to administrators
      // await accessService.requestAccess({
      //   resource: route.path,
      //   user_id: user.value?.id,
      //   reason: 'User requested access via 403 page'
      // })
      
      uiStore.showSuccess(
        'Access request sent! Your administrator will review your request and contact you soon.'
      )
    } catch (error: any) {
      console.error('Failed to send access request:', error)
      uiStore.showError('Failed to send access request. Please try again later.')
    }
  }
}

/**
 * Contact support
 */
function contactSupport() {
  uiStore.showInfo('Support contact functionality would be implemented here.')
  
  // In a real app, this might:
  // - Open a support chat widget
  // - Navigate to a contact form
  // - Open the default email client with pre-filled subject
  // - Show a help center with access-related articles
}

// Log 403 for analytics and monitoring (in a real app)
console.warn(`403 Error: Unauthorized access attempt - ${route.fullPath}`, {
  user: user.value?.email,
  role: user.value?.role,
  timestamp: new Date().toISOString()
})

// Meta title for SEO
document.title = '403 - Access Denied'
</script>

<style scoped>
.unauthorized-view {
  min-height: 100vh;
  background: linear-gradient(135deg, 
    rgba(var(--v-theme-warning), 0.02) 0%, 
    rgba(var(--v-theme-error), 0.02) 100%
  );
}

.error-illustration {
  position: relative;
}

.error-code {
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 2rem;
}

.error-code .text-h1 {
  font-size: 6rem !important;
  line-height: 1;
  text-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

.error-message h1 {
  color: rgb(var(--v-theme-on-background));
}

.action-buttons {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 8px;
}

.v-btn {
  border-radius: 12px;
  text-transform: none;
  font-weight: 500;
}

.v-card {
  border-radius: 16px;
}

.v-list-item {
  border-radius: 8px;
  margin-bottom: 4px;
}

.v-list-item:hover {
  background-color: rgba(var(--v-theme-warning), 0.1);
}

.v-avatar {
  border: 2px solid rgba(var(--v-theme-primary), 0.2);
}

/* Animations */
.error-illustration {
  animation: shake 3s ease-in-out infinite;
}

@keyframes shake {
  0%, 100% {
    transform: translateX(0);
  }
  25% {
    transform: translateX(-5px);
  }
  75% {
    transform: translateX(5px);
  }
}

.error-code {
  animation: glow 2s ease-in-out infinite alternate;
}

@keyframes glow {
  from {
    filter: drop-shadow(0 0 5px rgba(var(--v-theme-warning), 0.5));
  }
  to {
    filter: drop-shadow(0 0 20px rgba(var(--v-theme-warning), 0.8));
  }
}

/* Hover effects */
.v-card {
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.v-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12);
}

/* Gap utility */
.gap-2 {
  gap: 8px;
}

/* Responsive adjustments */
@media (max-width: 960px) {
  .error-code .text-h1 {
    font-size: 4rem !important;
  }
  
  .error-illustration .v-icon {
    font-size: 80px !important;
  }
  
  .action-buttons {
    flex-direction: column;
    align-items: center;
  }
  
  .action-buttons .v-btn {
    width: 250px;
    margin: 4px 0;
  }
}

@media (max-width: 600px) {
  .error-code .text-h1 {
    font-size: 3rem !important;
  }
  
  .error-illustration .v-icon {
    font-size: 60px !important;
  }
  
  .error-code .v-icon {
    font-size: 60px !important;
  }
  
  .v-container {
    padding: 16px;
  }
  
  .error-message h1 {
    font-size: 2rem !important;
  }
  
  .error-message .text-h6 {
    font-size: 1.2rem !important;
  }
  
  .d-flex.justify-center.gap-2 {
    flex-direction: column;
    gap: 8px;
  }
}

/* Dark theme adjustments */
.v-theme--dark .unauthorized-view {
  background: linear-gradient(135deg, 
    rgba(var(--v-theme-warning), 0.05) 0%, 
    rgba(var(--v-theme-error), 0.05) 100%
  );
}

.v-theme--dark .error-code .text-h1 {
  text-shadow: 0 4px 8px rgba(255, 255, 255, 0.1);
}
</style>
