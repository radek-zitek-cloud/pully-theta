/**
 * Authentication Layout Component
 * 
 * Layout wrapper for authentication pages (login, register).
 * Provides a centered, responsive design with branding.
 */

<template>
  <VApp>
    <VMain>
      <VContainer fluid class="auth-container">
        <VRow class="fill-height" justify="center" align="center">
          <VCol cols="12" sm="8" md="6" lg="4" xl="3">
            <!-- App Branding -->
            <div class="text-center mb-8">
              <VAvatar
                :size="80"
                color="primary"
                class="mb-4"
              >
                <VIcon size="40">mdi-account-circle</VIcon>
              </VAvatar>
              
              <h1 class="text-h4 font-weight-bold mb-2">
                {{ appTitle }}
              </h1>
              
              <p class="text-subtitle-1 text-medium-emphasis">
                Welcome to your secure authentication portal
              </p>
            </div>

            <!-- Auth Form Container -->
            <VCard
              elevation="8"
              rounded="lg"
              class="auth-card"
            >
              <RouterView />
            </VCard>

            <!-- Footer Links -->
            <div class="text-center mt-6">
              <VBtn
                variant="text"
                size="small"
                @click="showHelp"
              >
                Help & Support
              </VBtn>
              
              <span class="mx-2 text-medium-emphasis">•</span>
              
              <VBtn
                variant="text"
                size="small"
                @click="showPrivacy"
              >
                Privacy Policy
              </VBtn>
              
              <span class="mx-2 text-medium-emphasis">•</span>
              
              <VBtn
                variant="text"
                size="small"
                @click="showTerms"
              >
                Terms of Service
              </VBtn>
            </div>

            <!-- Version Info -->
            <div class="text-center mt-4">
              <p class="text-caption text-medium-emphasis">
                Version {{ appVersion }}
              </p>
            </div>
          </VCol>
        </VRow>
      </VContainer>
    </VMain>

    <!-- Theme Toggle (Floating) -->
    <VBtn
      icon
      :color="themeIcon === 'mdi-weather-night' ? 'yellow-darken-3' : 'blue-darken-2'"
      class="theme-toggle"
      elevation="4"
      @click="uiStore.toggleTheme"
      :aria-label="`Switch to ${nextTheme} theme`"
    >
      <VIcon>{{ themeIcon }}</VIcon>
    </VBtn>

    <!-- Background Elements -->
    <div class="auth-background">
      <div class="auth-background__shape auth-background__shape--1"></div>
      <div class="auth-background__shape auth-background__shape--2"></div>
      <div class="auth-background__shape auth-background__shape--3"></div>
    </div>
  </VApp>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useUIStore } from '@/stores'

// Store reference
const uiStore = useUIStore()

// Computed properties
const appTitle = computed(() => {
  return import.meta.env.VITE_APP_TITLE || 'Pully Theta'
})

const appVersion = computed(() => {
  return import.meta.env.VITE_APP_VERSION || '1.0.0'
})

const themeIcon = computed(() => {
  return uiStore.activeTheme === 'dark' ? 'mdi-weather-night' : 'mdi-weather-sunny'
})

const nextTheme = computed(() => {
  return uiStore.activeTheme === 'dark' ? 'light' : 'dark'
})

// Methods

/**
 * Show help information
 */
function showHelp() {
  uiStore.showInfo(
    'Need help? Contact our support team at support@example.com or visit our documentation.',
    {
      timeout: 10000,
      actions: [
        {
          label: 'Contact Support',
          handler: () => {
            window.open('mailto:support@example.com', '_blank')
          }
        }
      ]
    }
  )
}

/**
 * Show privacy policy
 */
function showPrivacy() {
  uiStore.showInfo('Privacy policy will be displayed here.')
}

/**
 * Show terms of service
 */
function showTerms() {
  uiStore.showInfo('Terms of service will be displayed here.')
}
</script>

<style scoped>
.auth-container {
  min-height: 100vh;
  background: linear-gradient(135deg, 
    rgba(var(--v-theme-primary), 0.1) 0%, 
    rgba(var(--v-theme-secondary), 0.05) 100%
  );
  position: relative;
  overflow: hidden;
}

.auth-card {
  backdrop-filter: blur(10px);
  background-color: rgba(var(--v-theme-surface), 0.9);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.1);
}

.theme-toggle {
  position: fixed;
  top: 24px;
  right: 24px;
  z-index: 1000;
}

/* Background decoration */
.auth-background {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  overflow: hidden;
}

.auth-background__shape {
  position: absolute;
  border-radius: 50%;
  background: linear-gradient(45deg, 
    rgba(var(--v-theme-primary), 0.1), 
    rgba(var(--v-theme-accent), 0.1)
  );
  animation: float 20s ease-in-out infinite;
}

.auth-background__shape--1 {
  width: 300px;
  height: 300px;
  top: -150px;
  left: -150px;
  animation-delay: 0s;
}

.auth-background__shape--2 {
  width: 200px;
  height: 200px;
  top: 50%;
  right: -100px;
  animation-delay: -7s;
}

.auth-background__shape--3 {
  width: 150px;
  height: 150px;
  bottom: -75px;
  left: 50%;
  transform: translateX(-50%);
  animation-delay: -14s;
}

@keyframes float {
  0%, 100% {
    transform: translateY(0px) rotate(0deg);
  }
  33% {
    transform: translateY(-20px) rotate(120deg);
  }
  66% {
    transform: translateY(20px) rotate(240deg);
  }
}

/* Dark theme adjustments */
[data-theme="dark"] .auth-container {
  background: linear-gradient(135deg, 
    rgba(var(--v-theme-primary), 0.2) 0%, 
    rgba(var(--v-theme-background), 1) 100%
  );
}

[data-theme="dark"] .auth-card {
  background-color: rgba(var(--v-theme-surface), 0.95);
  border-color: rgba(var(--v-theme-on-surface), 0.2);
}

/* Responsive adjustments */
@media (max-width: 600px) {
  .auth-container {
    padding: 16px;
  }
  
  .theme-toggle {
    top: 16px;
    right: 16px;
  }
  
  .auth-background__shape {
    display: none;
  }
  
  .text-h4 {
    font-size: 1.5rem !important;
  }
}

/* Reduced motion support */
@media (prefers-reduced-motion: reduce) {
  .auth-background__shape {
    animation: none;
  }
}

/* High contrast mode */
@media (prefers-contrast: high) {
  .auth-card {
    border-width: 2px;
    border-color: rgb(var(--v-theme-on-surface));
  }
}
</style>
