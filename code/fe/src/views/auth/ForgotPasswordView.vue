<!--
  Forgot Password View Component
  
  This component provides a user interface for requesting password reset.
  It allows users to enter their email address to receive a password reset link.
  
  Features:
  - Email validation and submission
  - Loading states during API calls
  - Success and error handling
  - Clean, accessible form design
  - Rate limiting protection (handled by backend)
  - Security-conscious messaging to prevent enumeration
-->

<template>
  <div class="forgot-password-container">
    <!-- Header Section -->
    <div class="text-center mb-8">
      <VIcon
        color="primary"
        size="48"
        class="mb-4"
      >
        mdi-lock-reset
      </VIcon>
      
      <h1 class="text-h4 font-weight-bold text-primary mb-2">
        Reset Your Password
      </h1>
      
      <p class="text-body-1 text-medium-emphasis mb-0">
        Enter your email address and we'll send you a link to reset your password.
      </p>
    </div>

    <!-- Success Message (shown after form submission) -->
    <VAlert
      v-if="isSubmitted"
      type="success"
      variant="tonal"
      class="mb-6"
      prominent
    >
      <VAlertTitle class="mb-2">
        Check Your Email
      </VAlertTitle>
      
      <p class="mb-2">
        If an account with that email address exists, we've sent you a password reset link.
      </p>
      
      <p class="text-caption mb-0">
        Check your email inbox and spam folder. The link will expire in 1 hour.
      </p>
    </VAlert>

    <!-- Forgot Password Form -->
    <VCard
      v-if="!isSubmitted"
      elevation="4"
      class="mx-auto forgot-password-card"
      max-width="400"
    >
      <VCardText class="pa-6">
        <VForm
          ref="formRef"
          v-model="formValid"
          @submit.prevent="handleSubmit"
        >
          <!-- Email Input -->
          <VTextField
            v-model="form.email"
            :rules="emailRules"
            :error-messages="fieldErrors.email"
            :disabled="isLoading"
            label="Email Address"
            placeholder="Enter your email address"
            type="email"
            variant="outlined"
            prepend-inner-icon="mdi-email"
            class="mb-4"
            autocomplete="email"
            required
            @blur="validateEmail"
            @input="clearFieldError('email')"
          />

          <!-- Submit Button -->
          <VBtn
            :loading="isLoading"
            :disabled="!formValid || isLoading"
            type="submit"
            color="primary"
            size="large"
            block
            class="mb-4"
          >
            <template #prepend>
              <VIcon>mdi-send</VIcon>
            </template>
            Send Reset Link
          </VBtn>

          <!-- Back to Login Link -->
          <div class="text-center">
            <VBtn
              :to="{ name: 'login' }"
              variant="text"
              color="primary"
              size="small"
              class="text-decoration-none"
            >
              <template #prepend>
                <VIcon size="small">mdi-arrow-left</VIcon>
              </template>
              Back to Login
            </VBtn>
          </div>
        </VForm>
      </VCardText>
    </VCard>

    <!-- Alternative Actions (shown after submission) -->
    <div
      v-if="isSubmitted"
      class="text-center mt-6"
    >
      <VBtn
        :to="{ name: 'login' }"
        variant="outlined"
        color="primary"
        class="me-3"
      >
        <template #prepend>
          <VIcon size="small">mdi-arrow-left</VIcon>
        </template>
        Back to Login
      </VBtn>

      <VBtn
        variant="text"
        color="primary"
        @click="resetForm"
      >
        <template #prepend>
          <VIcon size="small">mdi-refresh</VIcon>
        </template>
        Try Different Email
      </VBtn>
    </div>

    <!-- Help Section -->
    <VCard
      variant="tonal"
      color="info"
      class="mt-8 mx-auto"
      max-width="400"
    >
      <VCardText class="pa-4">
        <div class="d-flex align-center mb-2">
          <VIcon
            color="info"
            size="small"
            class="me-2"
          >
            mdi-information
          </VIcon>
          <span class="text-subtitle-2 font-weight-medium">Need Help?</span>
        </div>
        
        <p class="text-body-2 mb-2">
          If you don't receive the email within a few minutes:
        </p>
        
        <ul class="text-body-2 mb-0 ps-4">
          <li>Check your spam/junk folder</li>
          <li>Verify you entered the correct email address</li>
          <li>Contact support if you continue having issues</li>
        </ul>
      </VCardText>
    </VCard>
  </div>
</template>

<script setup lang="ts">
/**
 * Forgot Password View Component
 * 
 * Provides password reset request functionality with comprehensive
 * email validation, error handling, and user feedback.
 * 
 * @component ForgotPasswordView
 * @example
 * <ForgotPasswordView />
 */

import { ref, reactive, computed } from 'vue'
import { authService } from '@/services'
import { useUIStore } from '@/stores'
import type { ForgotPasswordRequest } from '@/types'

// ===== COMPOSABLES =====

const uiStore = useUIStore()

// ===== REACTIVE STATE =====

/**
 * Form validation reference
 */
const formRef = ref()

/**
 * Overall form validity state
 */
const formValid = ref(false)

/**
 * Loading state during API calls
 */
const isLoading = ref(false)

/**
 * Tracks whether form has been successfully submitted
 */
const isSubmitted = ref(false)

/**
 * Form data reactive object
 */
const form = reactive<ForgotPasswordRequest>({
  email: ''
})

/**
 * Field-specific error messages
 */
const fieldErrors = reactive<Record<string, string[]>>({
  email: []
})

// ===== COMPUTED PROPERTIES =====

/**
 * Email validation rules for the form field
 */
const emailRules = computed(() => [
  (value: string) => {
    if (!value) return 'Email address is required'
    if (value.length > 254) return 'Email address is too long'
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(value)) return 'Please enter a valid email address'
    
    return true
  }
])

// ===== METHODS =====

/**
 * Validate email field and update field errors
 * 
 * @description Performs client-side email validation and updates
 * the field error state for immediate user feedback.
 */
const validateEmail = (): void => {
  const rule = emailRules.value[0]
  const result = rule(form.email)
  
  if (result === true) {
    fieldErrors.email = []
  } else {
    fieldErrors.email = [result as string]
  }
}

/**
 * Clear field-specific error messages
 * 
 * @param field - The field name to clear errors for
 */
const clearFieldError = (field: keyof typeof fieldErrors): void => {
  fieldErrors[field] = []
}

/**
 * Reset the form to initial state
 * 
 * @description Clears all form data, errors, and submission state
 * to allow the user to try again with different credentials.
 */
const resetForm = (): void => {
  form.email = ''
  fieldErrors.email = []
  isSubmitted.value = false
  formValid.value = false
  formRef.value?.resetValidation()
}

/**
 * Handle form submission for password reset request
 * 
 * This method:
 * 1. Validates the form data
 * 2. Calls the forgot password API
 * 3. Shows success state regardless of outcome (security)
 * 4. Handles and logs any errors appropriately
 * 
 * @throws Will handle and display appropriate error messages to user
 */
const handleSubmit = async (): Promise<void> => {
  try {
    // Validate form before submission
    const { valid } = await formRef.value.validate()
    if (!valid) {
      uiStore.showError('Please correct the errors before submitting')
      return
    }

    isLoading.value = true

    // Call the forgot password API
    await authService.forgotPassword({
      email: form.email.trim().toLowerCase()
    })

    // Always show success state for security (prevent enumeration)
    isSubmitted.value = true

    // Log success for debugging (in development)
    if (process.env.NODE_ENV === 'development') {
      console.log('Password reset requested for:', form.email)
    }

  } catch (error) {
    console.error('Forgot password error:', error)

    // Still show success to prevent enumeration attacks
    // The backend will handle rate limiting and actual email sending
    isSubmitted.value = true

  } finally {
    isLoading.value = false
  }
}

// ===== METADATA =====

/**
 * Component metadata for Vue DevTools
 */
defineOptions({
  name: 'ForgotPasswordView'
})
</script>

<style scoped>
/**
 * Component-specific styles for the forgot password view
 * 
 * Provides responsive layout, consistent spacing, and
 * professional appearance aligned with the application design system.
 */

.forgot-password-container {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  padding: 2rem 1rem;
  background: linear-gradient(135deg, rgba(var(--v-theme-primary), 0.1) 0%, rgba(var(--v-theme-secondary), 0.1) 100%);
}

.forgot-password-card {
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
  border-radius: 16px;
  backdrop-filter: blur(10px);
  background: rgba(255, 255, 255, 0.95);
}

@media (max-width: 600px) {
  .forgot-password-container {
    padding: 1rem 0.5rem;
  }
  
  .forgot-password-card {
    margin: 0 0.5rem;
  }
}

/* Dark theme adjustments */
.v-theme--dark .forgot-password-card {
  background: rgba(var(--v-theme-surface), 0.95);
}

/* Focus and interaction states */
.v-text-field--focused {
  transform: translateY(-2px);
  transition: transform 0.2s ease;
}

/* Success state animations */
.v-alert {
  animation: slideIn 0.3s ease-out;
}

@keyframes slideIn {
  from {
    opacity: 0;
    transform: translateY(-10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* Button hover effects */
.v-btn:hover:not(.v-btn--disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  transition: all 0.2s ease;
}
</style>
