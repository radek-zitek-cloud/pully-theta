/**
 * Register View Component
 * 
 * User registration form with comprehensive validation, password confirmation,
 * and integration with the authentication service.
 */

<template>
  <VCardText class="pa-8">
    <!-- Header -->
    <div class="text-center mb-6">
      <h2 class="text-h5 font-weight-bold mb-2">
        Create Account
      </h2>
      <p class="text-body-2 text-medium-emphasis">
        Join us and start your journey today
      </p>
    </div>

    <!-- Registration Form -->
    <VForm
      ref="formRef"
      v-model="isFormValid"
      @submit.prevent="handleSubmit"
    >
      <!-- Name Fields Row -->
      <VRow class="mb-4">
        <VCol cols="6">
          <VTextField
            v-model="form.first_name"
            label="First Name"
            :rules="firstNameRules"
            :error-messages="getFieldErrors('first_name')"
            prepend-inner-icon="mdi-account"
            variant="outlined"
            autocomplete="given-name"
            required
          />
        </VCol>
        <VCol cols="6">
          <VTextField
            v-model="form.last_name"
            label="Last Name"
            :rules="lastNameRules"
            :error-messages="getFieldErrors('last_name')"
            variant="outlined"
            autocomplete="family-name"
            required
          />
        </VCol>
      </VRow>

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
        label="Password"
        :type="showPassword ? 'text' : 'password'"
        :rules="passwordRules"
        :error-messages="getFieldErrors('password')"
        prepend-inner-icon="mdi-lock"
        :append-inner-icon="showPassword ? 'mdi-eye' : 'mdi-eye-off'"
        variant="outlined"
        class="mb-4"
        autocomplete="new-password"
        required
        @click:append-inner="showPassword = !showPassword"
      />

      <!-- Password Confirmation Field -->
      <VTextField
        v-model="form.password_confirm"
        label="Confirm Password"
        :type="showPasswordConfirm ? 'text' : 'password'"
        :rules="passwordConfirmRules"
        :error-messages="getFieldErrors('password_confirm')"
        prepend-inner-icon="mdi-lock-check"
        :append-inner-icon="showPasswordConfirm ? 'mdi-eye' : 'mdi-eye-off'"
        variant="outlined"
        class="mb-4"
        autocomplete="new-password"
        required
        @click:append-inner="showPasswordConfirm = !showPasswordConfirm"
      />

      <!-- Password Strength Indicator -->
      <div v-if="form.password" class="mb-4">
        <div class="d-flex align-center mb-2">
          <span class="text-caption text-medium-emphasis mr-2">
            Password Strength:
          </span>
          <VChip
            :color="passwordStrength.color"
            size="small"
            variant="tonal"
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

      <!-- Terms and Privacy -->
      <VCheckbox
        v-model="acceptTerms"
        color="primary"
        class="mb-4"
        hide-details
      >
        <template #label>
          <span class="text-body-2">
            I agree to the 
            <VBtn
              variant="text"
              size="small"
              @click="showTerms"
              class="pa-0 text-decoration-underline"
            >
              Terms of Service
            </VBtn>
            and 
            <VBtn
              variant="text"
              size="small"
              @click="showPrivacy"
              class="pa-0 text-decoration-underline"
            >
              Privacy Policy
            </VBtn>
          </span>
        </template>
      </VCheckbox>

      <!-- Submit Button -->
      <VBtn
        type="submit"
        color="primary"
        size="large"
        block
        :loading="isLoading"
        :disabled="!isFormValid || !acceptTerms"
      >
        Create Account
      </VBtn>
    </VForm>
  </VCardText>

  <!-- Login Link -->
  <VDivider />
  <VCardActions class="justify-center pa-6">
    <span class="text-body-2 text-medium-emphasis mr-2">
      Already have an account?
    </span>
    <VBtn
      :to="{ name: 'login' }"
      variant="text"
      color="primary"
    >
      Sign In
    </VBtn>
  </VCardActions>
</template>

<script setup lang="ts">
import { ref, reactive, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore, useUIStore } from '@/stores'
import type { RegisterRequest } from '@/types'

// Store references
const authStore = useAuthStore()
const uiStore = useUIStore()
const router = useRouter()

// Template refs
const formRef = ref()

// Form state
const isFormValid = ref(false)
const isLoading = ref(false)
const showPassword = ref(false)
const showPasswordConfirm = ref(false)
const acceptTerms = ref(false)
const formErrors = ref<Record<string, string[]>>({})

// Form data
const form = reactive<RegisterRequest>({
  first_name: '',
  last_name: '',
  email: '',
  password: '',
  password_confirm: ''
})

// Validation rules
const firstNameRules = [
  (v: string) => !!v || 'First name is required',
  (v: string) => (v && v.length >= 1) || 'First name must be at least 1 character',
  (v: string) => (v && v.length <= 100) || 'First name must be less than 100 characters'
]

const lastNameRules = [
  (v: string) => !!v || 'Last name is required',
  (v: string) => (v && v.length >= 1) || 'Last name must be at least 1 character',
  (v: string) => (v && v.length <= 100) || 'Last name must be less than 100 characters'
]

const emailRules = [
  (v: string) => !!v || 'Email is required',
  (v: string) => /.+@.+\..+/.test(v) || 'Please enter a valid email address',
  (v: string) => (v && v.length <= 255) || 'Email must be less than 255 characters'
]

const passwordRules = [
  (v: string) => !!v || 'Password is required',
  (v: string) => (v && v.length >= 8) || 'Password must be at least 8 characters',
  (v: string) => (v && v.length <= 128) || 'Password must be less than 128 characters',
  (v: string) => /[A-Z]/.test(v) || 'Password must contain at least one uppercase letter',
  (v: string) => /[a-z]/.test(v) || 'Password must contain at least one lowercase letter',
  (v: string) => /\d/.test(v) || 'Password must contain at least one number',
  (v: string) => /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(v) || 'Password must contain at least one special character'
]

const passwordConfirmRules = [
  (v: string) => !!v || 'Password confirmation is required',
  (v: string) => v === form.password || 'Passwords do not match'
]

// Computed properties
const passwordStrength = computed(() => {
  const password = form.password
  if (!password) return { score: 0, text: 'None', color: 'grey' }

  let score = 0
  
  // Length check
  if (password.length >= 8) score++
  if (password.length >= 12) score++
  
  // Character variety checks
  if (/[a-z]/.test(password)) score++
  if (/[A-Z]/.test(password)) score++
  if (/\d/.test(password)) score++
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score++

  // Bonus for very long passwords
  if (password.length >= 16) score++

  const maxScore = 7
  const normalizedScore = Math.min(score, 4)

  const strengthLevels = [
    { text: 'Very Weak', color: 'error' },
    { text: 'Weak', color: 'warning' },
    { text: 'Fair', color: 'orange' },
    { text: 'Good', color: 'success' },
    { text: 'Strong', color: 'green-darken-2' }
  ]

  return {
    score: normalizedScore,
    ...strengthLevels[normalizedScore]
  }
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
  if (!isFormValid.value || !acceptTerms.value) return

  try {
    isLoading.value = true
    clearErrors()

    // Attempt registration
    const response = await authStore.register(form)

    // Show success message
    uiStore.showSuccess('Account created successfully! Please sign in with your new credentials.')

    // Redirect to login page
    router.push({ name: 'login' })

  } catch (error: any) {
    console.error('Registration failed:', error)

    // Handle validation errors
    if (error.details && typeof error.details === 'object') {
      formErrors.value = error.details
    } else {
      // Show general error message
      uiStore.showError(error.message || 'Registration failed. Please try again.')
    }

    // Clear sensitive fields on error
    form.password = ''
    form.password_confirm = ''
    showPassword.value = false
    showPasswordConfirm.value = false

  } finally {
    isLoading.value = false
  }
}

/**
 * Show terms of service
 */
function showTerms() {
  uiStore.showInfo('Terms of Service will be displayed here.')
}

/**
 * Show privacy policy
 */
function showPrivacy() {
  uiStore.showInfo('Privacy Policy will be displayed here.')
}
</script>

<style scoped>
.v-card-text {
  max-width: 500px;
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

/* Password strength indicator */
.v-progress-linear {
  border-radius: 2px;
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

/* Form layout adjustments */
.v-row {
  margin: 0;
}

.v-col {
  padding: 0 6px;
}

.v-col:first-child {
  padding-left: 0;
}

.v-col:last-child {
  padding-right: 0;
}

/* Terms and privacy links */
.text-decoration-underline {
  text-decoration: underline;
}

/* Responsive adjustments */
@media (max-width: 600px) {
  .v-card-text {
    padding: 24px 20px;
  }
  
  .v-card-actions {
    padding: 16px 20px 20px;
  }
  
  .v-row {
    flex-direction: column;
  }
  
  .v-col {
    padding: 0;
    margin-bottom: 16px;
  }
  
  .v-col:last-child {
    margin-bottom: 0;
  }
}
</style>
