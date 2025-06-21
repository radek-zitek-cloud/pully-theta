/**
 * Not Found (404) View Component
 * 
 * Displays a user-friendly 404 error page with navigation options
 * and helpful suggestions for users who encounter missing pages.
 */

<template>
  <div class="not-found-view">
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
              color="primary" 
              class="mb-4"
            >
              mdi-file-question-outline
            </VIcon>
            
            <div class="error-code">
              <span class="text-h1 font-weight-bold text-primary">4</span>
              <VIcon 
                size="80" 
                color="error" 
                class="mx-2"
              >
                mdi-emoticon-sad-outline
              </VIcon>
              <span class="text-h1 font-weight-bold text-primary">4</span>
            </div>
          </div>

          <!-- Error Message -->
          <div class="error-message mb-8">
            <h1 class="text-h3 font-weight-bold mb-4">
              Page Not Found
            </h1>
            <p class="text-h6 text-medium-emphasis mb-6">
              Oops! The page you're looking for doesn't exist or has been moved.
            </p>
            <p class="text-body-1 text-medium-emphasis">
              Don't worry, it happens to the best of us. Here are some helpful links instead:
            </p>
          </div>

          <!-- Action Buttons -->
          <div class="action-buttons mb-8">
            <VBtn
              :to="{ name: 'dashboard' }"
              color="primary"
              size="large"
              variant="elevated"
              prepend-icon="mdi-home"
              class="mr-4 mb-2"
            >
              Go Home
            </VBtn>
            
            <VBtn
              @click="goBack"
              variant="outlined"
              size="large"
              prepend-icon="mdi-arrow-left"
              class="mr-4 mb-2"
            >
              Go Back
            </VBtn>
            
            <VBtn
              @click="showSearchDialog"
              variant="text"
              size="large"
              prepend-icon="mdi-magnify"
              class="mb-2"
            >
              Search
            </VBtn>
          </div>

          <!-- Helpful Links -->
          <VCard 
            variant="tonal" 
            color="primary"
            class="mx-auto"
            max-width="500"
          >
            <VCardTitle class="text-center">
              <VIcon class="mr-2">mdi-compass</VIcon>
              Popular Pages
            </VCardTitle>
            <VCardText>
              <VList bg-color="transparent">
                <VListItem
                  :to="{ name: 'dashboard' }"
                  prepend-icon="mdi-view-dashboard"
                >
                  <VListItemTitle>Dashboard</VListItemTitle>
                  <VListItemSubtitle>
                    Your main control center
                  </VListItemSubtitle>
                </VListItem>
                
                <VListItem
                  :to="{ name: 'profile' }"
                  prepend-icon="mdi-account"
                >
                  <VListItemTitle>Profile</VListItemTitle>
                  <VListItemSubtitle>
                    View and edit your profile
                  </VListItemSubtitle>
                </VListItem>
                
                <VListItem
                  :to="{ name: 'settings' }"
                  prepend-icon="mdi-cog"
                >
                  <VListItemTitle>Settings</VListItemTitle>
                  <VListItemSubtitle>
                    Customize your experience
                  </VListItemSubtitle>
                </VListItem>
              </VList>
            </VCardText>
          </VCard>

          <!-- Contact Support -->
          <div class="contact-support mt-8">
            <p class="text-body-2 text-medium-emphasis mb-4">
              Still having trouble? We're here to help!
            </p>
            <VBtn
              variant="text"
              size="small"
              prepend-icon="mdi-help-circle"
              @click="contactSupport"
            >
              Contact Support
            </VBtn>
          </div>
        </VCol>
      </VRow>
    </VContainer>

    <!-- Search Dialog -->
    <VDialog
      v-model="searchDialog"
      max-width="600"
    >
      <VCard>
        <VCardTitle>
          <VIcon class="mr-2">mdi-magnify</VIcon>
          Search
        </VCardTitle>
        <VCardText>
          <VTextField
            v-model="searchQuery"
            label="What are you looking for?"
            variant="outlined"
            prepend-inner-icon="mdi-magnify"
            autofocus
            @keyup.enter="performSearch"
          />
        </VCardText>
        <VCardActions>
          <VSpacer />
          <VBtn
            @click="searchDialog = false"
            variant="text"
          >
            Cancel
          </VBtn>
          <VBtn
            @click="performSearch"
            color="primary"
            :disabled="!searchQuery.trim()"
          >
            Search
          </VBtn>
        </VCardActions>
      </VCard>
    </VDialog>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useUIStore } from '@/stores'

// Store references
const uiStore = useUIStore()
const router = useRouter()
const route = useRoute()

// Component state
const searchDialog = ref(false)
const searchQuery = ref('')

// Methods

/**
 * Navigate back to the previous page
 */
function goBack() {
  // Check if there is a previous page in history
  if (window.history.length > 1) {
    router.go(-1)
  } else {
    // If no history, go to dashboard
    router.push({ name: 'dashboard' })
  }
}

/**
 * Show search dialog
 */
function showSearchDialog() {
  searchDialog.value = true
  searchQuery.value = ''
}

/**
 * Perform search
 */
function performSearch() {
  if (!searchQuery.value.trim()) return

  searchDialog.value = false
  
  // In a real app, this would navigate to a search results page
  // or perform the search and show results
  uiStore.showInfo(`Search functionality for "${searchQuery.value}" would be implemented here.`)
  
  // Example: router.push({ name: 'search', query: { q: searchQuery.value } })
}

/**
 * Contact support
 */
function contactSupport() {
  uiStore.showInfo('Support contact functionality would be implemented here.')
  
  // In a real app, this might:
  // - Open a support chat widget
  // - Navigate to a contact form
  // - Open the default email client
  // - Show a help center
}

// Log 404 for analytics (in a real app)
console.warn(`404 Error: Page not found - ${route.fullPath}`)

// Meta title for SEO
document.title = '404 - Page Not Found'
</script>

<style scoped>
.not-found-view {
  min-height: 100vh;
  background: linear-gradient(135deg, 
    rgba(var(--v-theme-primary), 0.02) 0%, 
    rgba(var(--v-theme-secondary), 0.02) 100%
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
  background-color: rgba(var(--v-theme-primary), 0.1);
}

.contact-support {
  opacity: 0.8;
}

/* Animations */
.error-illustration {
  animation: float 3s ease-in-out infinite;
}

@keyframes float {
  0%, 100% {
    transform: translateY(0px);
  }
  50% {
    transform: translateY(-10px);
  }
}

.error-code {
  animation: pulse 2s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% {
    transform: scale(1);
  }
  50% {
    transform: scale(1.05);
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
    width: 200px;
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
}

/* Dark theme adjustments */
.v-theme--dark .not-found-view {
  background: linear-gradient(135deg, 
    rgba(var(--v-theme-primary), 0.05) 0%, 
    rgba(var(--v-theme-secondary), 0.05) 100%
  );
}

.v-theme--dark .error-code .text-h1 {
  text-shadow: 0 4px 8px rgba(255, 255, 255, 0.1);
}
</style>
