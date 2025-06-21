<!--
  Change Password View Component
  
  A secure, user-friendly interface for users to change their passwords.
  Features comprehensive validation, security best practices, and proper
  user feedback throughout the password change process.
  
  Features:
  - Current password verification
  - Strong password requirements with real-time feedback
  - Password confirmation validation
  - Security tips and guidelines
  - Responsive design with proper accessibility
  - Integration with authentication service
  
  Security Considerations:
  - Requires current password verification
  - Enforces strong password policies
  - Provides clear feedback on password strength
  - Handles authentication errors gracefully
  - Clears sensitive data after submission
-->

<template>
  <VContainer class="change-password-view">
    <VRow justify="center">
      <VCol
        cols="12"
        sm="8"
        md="6"
        lg="5"
        xl="4"
      >
        <!-- Header Section -->
        <div class="text-center mb-8">
          <VIcon
            icon="mdi-lock-reset"
            size="64"
            color="primary"
            class="mb-4"
          />
          <h1 class="text-h4 font-weight-bold mb-2">
            Change Password
          </h1>
          <p class="text-body-1 text-medium-emphasis">
            Create a new secure password for your account
          </p>
        </div>

        <!-- Change Password Form -->
        <VCard
          elevation="2"
          class="pa-6"
        >
          <VForm
            ref="formRef"
            v-model="formValid"
            @submit.prevent="handleSubmit"
          >
            <!-- Current Password Field -->
            <div class="mb-6">
              <VTextField
                v-model="formData.currentPassword"
                :type="showCurrentPassword ? 'text' : 'password'"
                :append-inner-icon="showCurrentPassword ? 'mdi-eye-off' : 'mdi-eye'"
                :rules="currentPasswordRules"
                :loading="isSubmitting"
                :disabled="isSubmitting"
                label="Current Password"
                placeholder="Enter your current password"
                variant="outlined"
                density="comfortable"
                class="mb-2"
                @click:append-inner="showCurrentPassword = !showCurrentPassword"
              />
              <div class="text-caption text-medium-emphasis">
                We need to verify your current password for security
              </div>
            </div>

            <!-- New Password Field -->
            <div class="mb-6">
              <VTextField
                v-model="formData.newPassword"
                :type="showNewPassword ? 'text' : 'password'"
                :append-inner-icon="showNewPassword ? 'mdi-eye-off' : 'mdi-eye'"
                :rules="newPasswordRules"
                :loading="isSubmitting"
                :disabled="isSubmitting"
                label="New Password"
                placeholder="Create a strong password"
                variant="outlined"
                density="comfortable"
                class="mb-2"
                @click:append-inner="showNewPassword = !showNewPassword"
                @input="validatePasswordStrength"
              />
              
              <!-- Password Strength Indicator -->
              <div
                v-if="formData.newPassword"
                class="mt-2"
              >
                <div class="d-flex align-center mb-2">
                  <span class="text-caption me-2">Password Strength:</span>
                  <VChip
                    :color="passwordStrength.color"
                    size="small"
                    variant="flat"
                  >
                    {{ passwordStrength.text }}
                  </VChip>
                </div>
                <VProgressLinear
                  :model-value="passwordStrength.score * 25"
                  :color="passwordStrength.color"
                  height="4"
                  rounded
                />
              </div>
            </div>

            <!-- Confirm Password Field -->
            <div class="mb-6">
              <VTextField
                v-model="formData.confirmPassword"
                :type="showConfirmPassword ? 'text' : 'password'"
                :append-inner-icon="showConfirmPassword ? 'mdi-eye-off' : 'mdi-eye'"
                :rules="confirmPasswordRules"
                :loading="isSubmitting"
                :disabled="isSubmitting"
                label="Confirm New Password"
                placeholder="Confirm your new password"
                variant="outlined"
                density="comfortable"
                @click:append-inner="showConfirmPassword = !showConfirmPassword"
              />
            </div>

            <!-- Password Requirements -->
            <VCard
              variant="tonal"
              color="info"
              class="mb-6"
            >
              <VCardText class="py-4">
                <div class="text-subtitle-2 mb-3">
                  <VIcon
                    icon="mdi-information"
                    size="18"
                    class="me-2"
                  />
                  Password Requirements
                </div>
                <VList
                  density="compact"
                  class="pa-0"
                >
                  <VListItem
                    v-for="requirement in passwordRequirements"
                    :key="requirement.text"
                    class="px-0"
                  >
                    <template #prepend>
                      <VIcon
                        :icon="requirement.met ? 'mdi-check-circle' : 'mdi-circle-outline'"
                        :color="requirement.met ? 'success' : 'medium-emphasis'"
                        size="16"
                      />
                    </template>
                    <VListItemTitle
                      :class="requirement.met ? 'text-success' : 'text-medium-emphasis'"
                      class="text-caption"
                    >
                      {{ requirement.text }}
                    </VListItemTitle>
                  </VListItem>
                </VList>
              </VCardText>
            </VCard>

            <!-- Action Buttons -->
            <div class="d-flex flex-column flex-sm-row gap-3">
              <VBtn
                :loading="isSubmitting"
                :disabled="!formValid || isSubmitting"
                type="submit"
                color="primary"
                size="large"
                class="flex-grow-1"
              >
                <VIcon
                  icon="mdi-lock-check"
                  start
                />
                Update Password
              </VBtn>
              
              <VBtn
                :disabled="isSubmitting"
                variant="outlined"
                size="large"
                class="flex-grow-1"
                @click="handleCancel"
              >
                <VIcon
                  icon="mdi-cancel"
                  start
                />
                Cancel
              </VBtn>
            </div>
          </VForm>
        </VCard>

        <!-- Security Tips -->
        <VCard
          variant="outlined"
          class="mt-6"
        >
          <VCardText>
            <div class="text-subtitle-2 mb-3">
              <VIcon
                icon="mdi-shield-check"
                size="18"
                class="me-2"
              />
              Security Tips
            </div>
            <VList
              density="compact"
              class="pa-0"
            >
              <VListItem class="px-0">
                <VListItemTitle class="text-caption">
                  Use a unique password that you don't use elsewhere
                </VListItemTitle>
              </VListItem>
              <VListItem class="px-0">
                <VListItemTitle class="text-caption">
                  Consider using a password manager to generate and store secure passwords
                </VListItemTitle>
              </VListItem>
              <VListItem class="px-0">
                <VListItemTitle class="text-caption">
                  Enable two-factor authentication for additional security
                </VListItemTitle>
              </VListItem>
            </VList>
          </VCardText>
        </VCard>
      </VCol>
    </VRow>
  </VContainer>
</template>

<script setup lang="ts">
/**
 * Change Password View Component Script
 * 
 * Handles the complete password change workflow with comprehensive
 * validation, security measures, and user experience considerations.
 * 
 * Features:
 * - Real-time password strength analysis
 * - Current password verification
 * - Password confirmation validation
 * - Security best practices enforcement
 * - Proper error handling and user feedback
 */

import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore, useUIStore } from '@/stores'

// Types
interface ChangePasswordForm {
  currentPassword: string
  newPassword: string
  confirmPassword: string
}

interface PasswordRequirement {
  text: string
  met: boolean
  regex?: RegExp
  minLength?: number
}

interface PasswordStrength {
  score: number
  text: string
  color: string
}

// Composables
const router = useRouter()
const authStore = useAuthStore()
const uiStore = useUIStore()

// Reactive state
const formRef = ref()
const formValid = ref(false)
const isSubmitting = ref(false)

// Form visibility toggles
const showCurrentPassword = ref(false)
const showNewPassword = ref(false)
const showConfirmPassword = ref(false)

// Form data
const formData = reactive<ChangePasswordForm>({
  currentPassword: '',
  newPassword: '',
  confirmPassword: ''
})

/**
 * Password validation rules
 * 
 * Comprehensive set of validation rules that ensure password security
 * and provide clear feedback to users about password requirements.
 */
const currentPasswordRules = [
  (v: string) => !!v || 'Current password is required',
  (v: string) => v?.length >= 1 || 'Please enter your current password'
]

const newPasswordRules = [
  (v: string) => !!v || 'New password is required',
  (v: string) => v?.length >= 8 || 'Password must be at least 8 characters',
  (v: string) => /(?=.*[a-z])/.test(v) || 'Password must contain lowercase letters',
  (v: string) => /(?=.*[A-Z])/.test(v) || 'Password must contain uppercase letters',  
  (v: string) => /(?=.*\d)/.test(v) || 'Password must contain numbers',
  (v: string) => /(?=.*[@$!%*?&])/.test(v) || 'Password must contain special characters',
  (v: string) => v !== formData.currentPassword || 'New password must be different from current password'
]

const confirmPasswordRules = [
  (v: string) => !!v || 'Password confirmation is required',
  (v: string) => v === formData.newPassword || 'Passwords do not match'
]

/**
 * Password requirements tracking
 * 
 * Real-time tracking of password requirements to provide
 * visual feedback to users about password compliance.
 */
const passwordRequirements = computed<PasswordRequirement[]>(() => [
  {
    text: 'At least 8 characters long',
    met: formData.newPassword.length >= 8
  },
  {
    text: 'Contains lowercase letters (a-z)',
    met: /(?=.*[a-z])/.test(formData.newPassword)
  },
  {
    text: 'Contains uppercase letters (A-Z)',
    met: /(?=.*[A-Z])/.test(formData.newPassword)
  },
  {
    text: 'Contains numbers (0-9)',
    met: /(?=.*\d)/.test(formData.newPassword)
  },
  {
    text: 'Contains special characters (@$!%*?&)',
    met: /(?=.*[@$!%*?&])/.test(formData.newPassword)
  },
  {
    text: 'Different from current password',
    met: formData.newPassword !== formData.currentPassword && formData.newPassword.length > 0
  }
])

/**
 * Password strength calculation
 * 
 * Analyzes password strength based on various criteria and provides
 * visual feedback to help users create stronger passwords.
 * 
 * @returns {PasswordStrength} Object containing strength score, text, and color
 */
const passwordStrength = computed<PasswordStrength>(() => {
  const password = formData.newPassword
  if (!password) {
    return { score: 0, text: 'None', color: 'grey' }
  }

  let score = 0
  const requirements = passwordRequirements.value

  // Calculate score based on met requirements
  requirements.forEach(req => {
    if (req.met) score++
  })

  // Additional scoring for length and complexity
  if (password.length >= 12) score += 0.5
  if (password.length >= 16) score += 0.5
  if (/(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/.test(password)) score += 0.5

  // Normalize score to 0-4 range
  const normalizedScore = Math.min(4, score)

  // Determine strength level
  if (normalizedScore < 2) {
    return { score: 1, text: 'Weak', color: 'error' }
  } else if (normalizedScore < 4) {
    return { score: 2, text: 'Fair', color: 'warning' }
  } else if (normalizedScore < 5) {
    return { score: 3, text: 'Good', color: 'info' }
  } else {
    return { score: 4, text: 'Strong', color: 'success' }
  }
})

/**
 * Validate password strength on input
 * 
 * Triggers validation when the password field changes to provide
 * real-time feedback on password strength and requirements.
 */
function validatePasswordStrength() {
  // Trigger reactivity for password requirements
  // The computed properties will automatically update
}

/**
 * Handle form submission
 * 
 * Processes the password change request with proper validation,
 * error handling, and user feedback throughout the process.
 */
async function handleSubmit() {
  if (!formValid.value) {
    uiStore.showError('Please fix the form errors before submitting')
    return
  }

  isSubmitting.value = true

  try {
    // Import auth service directly since store is having issues
    const { authService } = await import('@/services')
    
    // Change password through auth service
    await authService.changePassword({
      currentPassword: formData.currentPassword,
      newPassword: formData.newPassword,
      confirmPassword: formData.confirmPassword
    })

    // Clear sensitive form data
    clearFormData()

    // Show success message
    uiStore.showSuccess('Password changed successfully! Please log in with your new password.')

    // For security, logout and redirect to login
    await authStore.logout()
    await router.push({ name: 'login' })

  } catch (error: any) {
    console.error('Password change failed:', error)
    
    // Handle specific error cases
    const errorMessage = error?.response?.data?.message || 
                        error?.message || 
                        'Failed to change password. Please try again.'

    uiStore.showError(errorMessage)

    // Clear only the current password field on error for security
    formData.currentPassword = ''
    
  } finally {
    isSubmitting.value = false
  }
}

/**
 * Handle cancel action
 * 
 * Safely cancels the password change process and returns the user
 * to the previous page with proper cleanup of sensitive data.
 */
function handleCancel() {
  // Clear sensitive form data
  clearFormData()
  
  // Navigate back to profile or settings
  router.back()
}

/**
 * Clear form data
 * 
 * Securely clears all form fields to prevent sensitive data
 * from remaining in memory longer than necessary.
 */
function clearFormData() {
  formData.currentPassword = ''
  formData.newPassword = ''
  formData.confirmPassword = ''
  
  // Reset form validation state
  if (formRef.value) {
    formRef.value.resetValidation()
  }
}

/**
 * Component lifecycle - mounted
 * 
 * Performs initial setup and validation when the component is mounted.
 * Ensures user is authenticated and has proper permissions.
 */
onMounted(() => {
  // Ensure user is authenticated
  if (!authStore.isAuthenticated) {
    uiStore.showWarning('Please log in to change your password')
    router.push({ name: 'login' })
    return
  }

  // Focus on the first input field for better UX
  // This will be handled by the VTextField component
})
</script>

<style scoped>
/**
 * Component-specific styles
 * 
 * Styles specific to the change password view that enhance
 * the user experience and maintain visual consistency.
 */

.change-password-view {
  min-height: calc(100vh - 200px);
  padding: 2rem 1rem;
}

/* Enhanced form styling */
.v-form {
  width: 100%;
}

/* Password strength indicator styling */
.v-progress-linear {
  border-radius: 4px;
}

/* Security tips styling */
.v-list-item-title {
  line-height: 1.4;
}

/* Responsive adjustments */
@media (max-width: 600px) {
  .change-password-view {
    padding: 1rem 0.5rem;
  }
  
  .pa-6 {
    padding: 1rem !important;
  }
}

/* Button group responsive layout */
@media (max-width: 600px) {
  .d-flex.flex-column.flex-sm-row {
    gap: 0.75rem;
  }
  
  .flex-grow-1 {
    width: 100%;
  }
}

/* Enhanced visual feedback for password requirements */
.text-success {
  transition: color 0.3s ease;
}

.text-medium-emphasis {
  transition: color 0.3s ease;
}
</style>
