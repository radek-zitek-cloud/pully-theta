/**
 * Login View Component
 * 
 * User authentication form with email/password login, form validation,
 * and remember me functionality. Integrates with the authentication service.
 */

<template>
  <VCardText class="pa-8">
    <!-- Header -->
    <div class="text-center mb-6">
      <h2 class="text-h5 font-weight-bold mb-2">
        Welcome Back
      </h2>
      <p class="text-body-2 text-medium-emphasis">
        Sign in to your account to continue
      </p>
    </div>

    <!-- Login Form -->
    <VForm
      ref="formRef"
      v-model="isFormValid"
      @submit.prevent="handleSubmit"
    >
      <!-- Email Field -->
      <VTextField
        v-model="form.email"
        label="Email"
        type="email"
        :rules="emailRules"
        :error-messages="getFieldErrors('email')"
        prepend-inner-icon="mdi-email"
        variant="outlined"
        class="mb-4"
        autocomplete="email"
        required
      />

      <!-- Password Field -->
      <VTextField
        v-model="form.password"
        :label="'Password'"
        :type="showPassword ? 'text' : 'password'"
        :rules="passwordRules"
        :error-messages="getFieldErrors('password')"
        prepend-inner-icon="mdi-lock"
        :append-inner-icon="showPassword ? 'mdi-eye' : 'mdi-eye-off'"
        variant="outlined"
        class="mb-4"
        autocomplete="current-password"
        required
        @click:append-inner="showPassword = !showPassword"
      />

      <!-- Remember Me -->
      <VCheckbox
        v-model="form.remember_me"
        label="Remember me"
        color="primary"
        class="mb-4"
        hide-details
      />

      <!-- Submit Button -->
      <VBtn
        type="submit"
        color="primary"
        size="large"
        block
        :loading="isLoading"
        :disabled="!isFormValid"
      >
        Sign In
      </VBtn>
    </VForm>

    <!-- Forgot Password Link -->
    <div class="text-center mt-4">
      <VBtn
        variant="text"
        size="small"
        @click="handleForgotPassword"
      >
        Forgot your password?
      </VBtn>
    </div>
  </VCardText>

  <!-- Register Link -->
  <VDivider />
  <VCardActions class="justify-center pa-6">
    <span class="text-body-2 text-medium-emphasis mr-2">
      Don't have an account?
    </span>
    <VBtn
      :to="{ name: 'register' }"
      variant="text"
      color="primary"
    >
      Sign Up
    </VBtn>
  </VCardActions>
</template>

<script setup lang="ts">
import { ref, reactive, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore, useUIStore } from '@/stores'
import type { LoginRequest } from '@/types'

// Store references
const authStore = useAuthStore()
const uiStore = useUIStore()
const router = useRouter()
const route = useRoute()

// Template refs
const formRef = ref()

// Form state
const isFormValid = ref(false)
const isLoading = ref(false)
const showPassword = ref(false)
const formErrors = ref<Record<string, string[]>>({})

// Form data
const form = reactive<LoginRequest>({
  email: '',
  password: '',
  remember_me: false
})

// Validation rules
const emailRules = [
  (v: string) => !!v || 'Email is required',
  (v: string) => /.+@.+\..+/.test(v) || 'Please enter a valid email address'
]

const passwordRules = [
  (v: string) => !!v || 'Password is required',
  (v: string) => v.length >= 8 || 'Password must be at least 8 characters'
]

// Computed properties
const redirectPath = computed(() => {
  return (route.query.redirect as string) || '/dashboard'
})

// Methods

/**
 * Get validation errors for a specific field
 * 
 * @param fieldName - Form field name
 * @returns Array of error messages
 */
function getFieldErrors(fieldName: string): string[] {
  return formErrors.value[fieldName] || []
}

/**
 * Clear all form errors
 */
function clearErrors() {
  formErrors.value = {}
}

/**
 * Handle form submission
 */
async function handleSubmit() {
  if (!isFormValid.value) return

  try {
    isLoading.value = true
    clearErrors()

    // Attempt login
    await authStore.login(form)

    // Show success message
    uiStore.showSuccess(`Welcome back, ${authStore.user?.first_name}!`)

    // Redirect to intended page
    router.push(redirectPath.value)

  } catch (error: any) {
    console.error('Login failed:', error)

    // Handle validation errors
    if (error.details && typeof error.details === 'object') {
      formErrors.value = error.details
    } else {
      // Show general error message
      uiStore.showError(error.message || 'Login failed. Please check your credentials.')
    }

    // Reset password field on error
    form.password = ''
    showPassword.value = false

  } finally {
    isLoading.value = false
  }
}

/**
 * Handle forgot password action
 * 
 * Navigates the user to the forgot password page where they can
 * enter their email address to receive a password reset link.
 */
function handleForgotPassword() {
  router.push({ name: 'forgot-password' })
}

/**
 * Pre-fill demo credentials (development only)
 */
function fillDemoCredentials() {
  if (import.meta.env.DEV) {
    form.email = 'demo@example.com'
    form.password = 'demo123456'
    form.remember_me = true
  }
}

// Development helper
if (import.meta.env.DEV) {
  console.log('Development mode: Use fillDemoCredentials() in console to pre-fill form')
  ;(window as any).fillDemoCredentials = fillDemoCredentials
}
</script>

<style scoped>
.v-card-text {
  max-width: 400px;
  margin: 0 auto;
}

.v-text-field {
  margin-bottom: 0;
}

.v-text-field :deep(.v-field) {
  border-radius: 12px;
}

.v-btn {
  border-radius: 12px;
  text-transform: none;
  font-weight: 500;
}

.v-checkbox {
  margin-bottom: 0;
}

.v-checkbox :deep(.v-selection-control__wrapper) {
  margin-right: 8px;
}

/* Focus styles for accessibility */
.v-text-field:focus-within {
  transform: translateY(-1px);
  transition: transform 0.2s ease;
}

/* Error state styling */
.v-text-field--error :deep(.v-field) {
  animation: shake 0.5s ease-in-out;
}

@keyframes shake {
  0%, 100% { transform: translateX(0); }
  25% { transform: translateX(-4px); }
  75% { transform: translateX(4px); }
}

/* Loading state */
.v-btn--loading {
  pointer-events: none;
}

/* Responsive adjustments */
@media (max-width: 600px) {
  .v-card-text {
    padding: 24px 20px;
  }
  
  .v-card-actions {
    padding: 16px 20px 20px;
  }
}
</style>
