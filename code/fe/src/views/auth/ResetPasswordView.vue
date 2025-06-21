<!--
  Reset Password View Component
  
  This component provides the interface for completing password reset
  using a token received via email. It allows users to set a new password.
  
  Features:
  - Token validation from URL parameters
  - New password form with confirmation
  - Password strength validation
  - Security best practices
  - Comprehensive error handling
  - Success state with login redirect
-->

<template>
  <div class="reset-password-container">
    <!-- Header Section -->
    <div class="text-center mb-8">
      <VIcon
        :color="isTokenValid ? 'primary' : 'error'"
        size="48"
        class="mb-4"
      >
        {{ isTokenValid ? 'mdi-lock-reset' : 'mdi-lock-alert' }}
      </VIcon>
      
      <h1 class="text-h4 font-weight-bold mb-2">
        {{ isTokenValid ? 'Create New Password' : 'Invalid Reset Link' }}
      </h1>
      
      <p class="text-body-1 text-medium-emphasis mb-0">
        {{ 
          isTokenValid 
            ? 'Please enter your new password below.' 
            : 'This password reset link is invalid or has expired.' 
        }}
      </p>
    </div>

    <!-- Invalid Token Message -->
    <VAlert
      v-if="!isTokenValid"
      type="error"
      variant="tonal"
      class="mb-6 mx-auto"
      max-width="400"
      prominent
    >
      <VAlertTitle class="mb-2">
        Link Not Valid
      </VAlertTitle>
      
      <p class="mb-2">
        This password reset link is either invalid, expired, or has already been used.
      </p>
      
      <p class="text-caption mb-0">
        Password reset links expire after 1 hour for security reasons.
      </p>
    </VAlert>

    <!-- Success Message (after password reset) -->
    <VAlert
      v-if="isResetComplete"
      type="success"
      variant="tonal"
      class="mb-6 mx-auto"
      max-width="400"
      prominent
    >
      <VAlertTitle class="mb-2">
        Password Reset Successfully
      </VAlertTitle>
      
      <p class="mb-2">
        Your password has been updated. You can now sign in with your new password.
      </p>
      
      <VBtn
        color="success"
        variant="outlined"
        size="small"
        :to="{ name: 'login' }"
        class="mt-2"
      >
        <template #prepend>
          <VIcon size="small">mdi-login</VIcon>
        </template>
        Sign In Now
      </VBtn>
    </VAlert>

    <!-- Reset Password Form -->
    <VCard
      v-if="isTokenValid && !isResetComplete"
      elevation="4"
      class="mx-auto reset-password-card"
      max-width="400"
    >
      <VCardText class="pa-6">
        <VForm
          ref="formRef"
          v-model="formValid"
          @submit.prevent="handleSubmit"
        >
          <!-- New Password Input -->
          <VTextField
            v-model="form.newPassword"
            :rules="passwordRules"
            :error-messages="fieldErrors.newPassword"
            :disabled="isLoading"
            :type="showNewPassword ? 'text' : 'password'"
            label="New Password"
            placeholder="Enter your new password"
            variant="outlined"
            prepend-inner-icon="mdi-lock"
            class="mb-4"
            autocomplete="new-password"
            required
            @blur="validatePassword"
            @input="clearFieldError('newPassword')"
          >
            <template #append-inner>
              <VBtn
                :icon="showNewPassword ? 'mdi-eye-off' : 'mdi-eye'"
                variant="text"
                size="small"
                @click="showNewPassword = !showNewPassword"
              />
            </template>
          </VTextField>

          <!-- Confirm Password Input -->
          <VTextField
            v-model="form.confirmPassword"
            :rules="confirmPasswordRules"
            :error-messages="fieldErrors.confirmPassword"
            :disabled="isLoading"
            :type="showConfirmPassword ? 'text' : 'password'"
            label="Confirm New Password"
            placeholder="Confirm your new password"
            variant="outlined"
            prepend-inner-icon="mdi-lock-check"
            class="mb-4"
            autocomplete="new-password"
            required
            @blur="validateConfirmPassword"
            @input="clearFieldError('confirmPassword')"
          >
            <template #append-inner>
              <VBtn
                :icon="showConfirmPassword ? 'mdi-eye-off' : 'mdi-eye'"
                variant="text"
                size="small"
                @click="showConfirmPassword = !showConfirmPassword"
              />
            </template>
          </VTextField>

          <!-- Password Requirements -->
          <VCard
            variant="outlined"
            class="mb-4 pa-3"
          >
            <div class="text-caption text-medium-emphasis mb-2">
              Password Requirements:
            </div>
            <ul class="text-caption">
              <li :class="{ 'text-success': hasMinLength, 'text-medium-emphasis': !hasMinLength }">
                At least 8 characters long
              </li>
              <li :class="{ 'text-success': hasUpperCase, 'text-medium-emphasis': !hasUpperCase }">
                At least one uppercase letter
              </li>
              <li :class="{ 'text-success': hasLowerCase, 'text-medium-emphasis': !hasLowerCase }">
                At least one lowercase letter
              </li>
              <li :class="{ 'text-success': hasNumber, 'text-medium-emphasis': !hasNumber }">
                At least one number
              </li>
              <li :class="{ 'text-success': hasSpecialChar, 'text-medium-emphasis': !hasSpecialChar }">
                At least one special character
              </li>
            </ul>
          </VCard>

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
              <VIcon>mdi-check</VIcon>
            </template>
            Update Password
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

    <!-- Alternative Actions for Invalid Token -->
    <div
      v-if="!isTokenValid"
      class="text-center mt-6"
    >
      <VBtn
        :to="{ name: 'forgot-password' }"
        color="primary"
        variant="outlined"
        class="me-3"
      >
        <template #prepend>
          <VIcon size="small">mdi-email</VIcon>
        </template>
        Request New Link
      </VBtn>

      <VBtn
        :to="{ name: 'login' }"
        variant="text"
        color="primary"
      >
        <template #prepend>
          <VIcon size="small">mdi-arrow-left</VIcon>
        </template>
        Back to Login
      </VBtn>
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * Reset Password View Component
 * 
 * Handles password reset completion using tokens from email links.
 * Provides secure password setting with comprehensive validation.
 * 
 * @component ResetPasswordView
 * @example
 * <ResetPasswordView />
 */

import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { authService } from '@/services'
import { useUIStore } from '@/stores'

// ===== COMPOSABLES =====

const route = useRoute()
const router = useRouter()
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
 * Tracks whether the reset token is valid
 */
const isTokenValid = ref(true)

/**
 * Tracks whether password reset is complete
 */
const isResetComplete = ref(false)

/**
 * Password visibility toggles
 */
const showNewPassword = ref(false)
const showConfirmPassword = ref(false)

/**
 * Form data reactive object
 */
const form = reactive({
  newPassword: '',
  confirmPassword: ''
})

/**
 * Field-specific error messages
 */
const fieldErrors = reactive<Record<string, string[]>>({
  newPassword: [],
  confirmPassword: []
})

/**
 * Reset token from URL parameters
 */
const resetToken = ref('')

// ===== COMPUTED PROPERTIES =====

/**
 * Password strength validation checks
 */
const hasMinLength = computed(() => form.newPassword.length >= 8)
const hasUpperCase = computed(() => /[A-Z]/.test(form.newPassword))
const hasLowerCase = computed(() => /[a-z]/.test(form.newPassword))
const hasNumber = computed(() => /[0-9]/.test(form.newPassword))
const hasSpecialChar = computed(() => /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(form.newPassword))

/**
 * Password validation rules for the form field
 */
const passwordRules = computed(() => [
  (value: string) => {
    if (!value) return 'New password is required'
    if (value.length < 8) return 'Password must be at least 8 characters long'
    if (value.length > 128) return 'Password must be less than 128 characters'
    if (!/[A-Z]/.test(value)) return 'Password must contain at least one uppercase letter'
    if (!/[a-z]/.test(value)) return 'Password must contain at least one lowercase letter'
    if (!/[0-9]/.test(value)) return 'Password must contain at least one number'
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(value)) return 'Password must contain at least one special character'
    return true
  }
])

/**
 * Confirm password validation rules
 */
const confirmPasswordRules = computed(() => [
  (value: string) => {
    if (!value) return 'Please confirm your new password'
    if (value !== form.newPassword) return 'Passwords do not match'
    return true
  }
])

// ===== METHODS =====

/**
 * Validate password field and update field errors
 */
const validatePassword = (): void => {
  const rule = passwordRules.value[0]
  const result = rule(form.newPassword)
  
  if (result === true) {
    fieldErrors.newPassword = []
  } else {
    fieldErrors.newPassword = [result as string]
  }
}

/**
 * Validate confirm password field and update field errors
 */
const validateConfirmPassword = (): void => {
  const rule = confirmPasswordRules.value[0]
  const result = rule(form.confirmPassword)
  
  if (result === true) {
    fieldErrors.confirmPassword = []
  } else {
    fieldErrors.confirmPassword = [result as string]
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
 * Handle form submission for password reset completion
 * 
 * This method:
 * 1. Validates the form data
 * 2. Calls the reset password API with token
 * 3. Shows success state and redirects to login
 * 4. Handles errors appropriately
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

    // Call the reset password API
    await authService.resetPassword({
      token: resetToken.value,
      new_password: form.newPassword
    })

    // Show success state
    isResetComplete.value = true
    uiStore.showSuccess('Password reset successfully! You can now sign in with your new password.')

    // Redirect to login after a delay
    setTimeout(() => {
      router.push({ name: 'login' })
    }, 3000)

  } catch (error: any) {
    console.error('Reset password error:', error)

    // Check if it's a token validation error
    if (error?.message?.includes('invalid') || error?.message?.includes('expired')) {
      isTokenValid.value = false
      uiStore.showError('The password reset link is invalid or has expired. Please request a new one.')
    } else {
      uiStore.showError('Failed to reset password. Please try again or request a new reset link.')
    }

  } finally {
    isLoading.value = false
  }
}

/**
 * Initialize component and validate token
 */
const initializeComponent = (): void => {
  // Get token from URL parameters
  const token = route.query.token as string
  
  if (!token) {
    isTokenValid.value = false
    uiStore.showError('No reset token provided in the URL')
    return
  }

  resetToken.value = token
  
  // Token validation will happen on form submission
  // This prevents unnecessary API calls on page load
}

// ===== LIFECYCLE =====

onMounted(() => {
  initializeComponent()
})

// ===== METADATA =====

/**
 * Component metadata for Vue DevTools
 */
defineOptions({
  name: 'ResetPasswordView'
})
</script>

<style scoped>
/**
 * Component-specific styles for the reset password view
 * 
 * Provides responsive layout, password strength indicators,
 * and consistent visual hierarchy.
 */

.reset-password-container {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  padding: 2rem 1rem;
  background: linear-gradient(135deg, rgba(var(--v-theme-primary), 0.1) 0%, rgba(var(--v-theme-secondary), 0.1) 100%);
}

.reset-password-card {
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
  border-radius: 16px;
  backdrop-filter: blur(10px);
  background: rgba(255, 255, 255, 0.95);
}

@media (max-width: 600px) {
  .reset-password-container {
    padding: 1rem 0.5rem;
  }
  
  .reset-password-card {
    margin: 0 0.5rem;
  }
}

/* Dark theme adjustments */
.v-theme--dark .reset-password-card {
  background: rgba(var(--v-theme-surface), 0.95);
}

/* Password requirements styling */
.v-card ul {
  list-style: none;
  padding-left: 0;
}

.v-card ul li {
  padding: 2px 0;
  position: relative;
  padding-left: 20px;
}

.v-card ul li::before {
  content: '✓';
  position: absolute;
  left: 0;
  top: 2px;
  font-weight: bold;
}

.v-card ul li.text-success::before {
  color: rgb(var(--v-theme-success));
}

.v-card ul li.text-medium-emphasis::before {
  color: rgb(var(--v-theme-on-surface-variant));
}

/* Form field animations */
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
