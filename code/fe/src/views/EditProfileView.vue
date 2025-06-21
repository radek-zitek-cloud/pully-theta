/**
 * Edit Profile View Component
 * 
 * Allows users to edit their profile information with validation,
 * avatar upload, and comprehensive form handling.
 */

<template>
  <div class="edit-profile-view">
    <!-- Header -->
    <div class="d-flex align-center mb-6">
      <VBtn
        :to="{ name: 'profile' }"
        icon="mdi-arrow-left"
        variant="text"
        class="mr-4"
      />
      <div>
        <h1 class="text-h4 font-weight-bold">Edit Profile</h1>
        <p class="text-body-1 text-medium-emphasis">
          Update your personal information and preferences
        </p>
      </div>
    </div>

    <VForm
      ref="formRef"
      v-model="isFormValid"
      @submit.prevent="handleSubmit"
    >
      <VRow>
        <!-- Avatar Section -->
        <VCol cols="12">
          <VCard elevation="2" class="mb-6">
            <VCardTitle>Profile Picture</VCardTitle>
            <VCardText>
              <div class="d-flex align-center">
                <VAvatar
                  :image="avatarPreview || user?.avatar_url"
                  size="100"
                  color="primary"
                  class="mr-6"
                >
                  <VIcon v-if="!avatarPreview && !user?.avatar_url" size="50">
                    mdi-account
                  </VIcon>
                </VAvatar>
                
                <div>
                  <VBtn
                    color="primary"
                    variant="outlined"
                    prepend-icon="mdi-upload"
                    class="mr-2 mb-2"
                    @click="triggerFileInput"
                  >
                    Upload Photo
                  </VBtn>
                  <VBtn
                    v-if="avatarPreview || user?.avatar_url"
                    color="error"
                    variant="outlined"
                    prepend-icon="mdi-delete"
                    class="mb-2"
                    @click="removeAvatar"
                  >
                    Remove
                  </VBtn>
                  <div class="text-caption text-medium-emphasis">
                    Supported formats: JPG, PNG, GIF (max 5MB)
                  </div>
                </div>
              </div>
              
              <input
                ref="fileInput"
                type="file"
                accept="image/*"
                style="display: none"
                @change="handleFileSelect"
              />
            </VCardText>
          </VCard>
        </VCol>

        <!-- Personal Information -->
        <VCol cols="12" md="6">
          <VCard elevation="2">
            <VCardTitle>Personal Information</VCardTitle>
            <VCardText>
              <VRow>
                <VCol cols="12" sm="6">
                  <VTextField
                    v-model="form.first_name"
                    label="First Name"
                    :rules="firstNameRules"
                    :error-messages="getFieldErrors('first_name')"
                    variant="outlined"
                    required
                  />
                </VCol>
                <VCol cols="12" sm="6">
                  <VTextField
                    v-model="form.last_name"
                    label="Last Name"
                    :rules="lastNameRules"
                    :error-messages="getFieldErrors('last_name')"
                    variant="outlined"
                    required
                  />
                </VCol>
              </VRow>

              <VTextField
                v-model="form.email"
                label="Email"
                type="email"
                :rules="emailRules"
                :error-messages="getFieldErrors('email')"
                variant="outlined"
                class="mb-4"
                required
              />

              <VTextField
                v-model="form.phone"
                label="Phone Number"
                :rules="phoneRules"
                :error-messages="getFieldErrors('phone')"
                variant="outlined"
                class="mb-4"
                prepend-inner-icon="mdi-phone"
              />

              <VTextField
                v-model="form.department"
                label="Department"
                :rules="departmentRules"
                :error-messages="getFieldErrors('department')"
                variant="outlined"
                prepend-inner-icon="mdi-domain"
              />
            </VCardText>
          </VCard>
        </VCol>

        <!-- Preferences -->
        <VCol cols="12" md="6">
          <VCard elevation="2">
            <VCardTitle>Preferences</VCardTitle>
            <VCardText>
              <VSelect
                v-model="form.timezone"
                label="Timezone"
                :items="timezoneOptions"
                item-title="label"
                item-value="value"
                variant="outlined"
                class="mb-4"
                prepend-inner-icon="mdi-clock"
              />

              <VSelect
                v-model="form.language"
                label="Language"
                :items="languageOptions"
                item-title="label"
                item-value="value"
                variant="outlined"
                class="mb-4"
                prepend-inner-icon="mdi-translate"
              />

              <VSelect
                v-model="form.date_format"
                label="Date Format"
                :items="dateFormatOptions"
                item-title="label"
                item-value="value"
                variant="outlined"
                prepend-inner-icon="mdi-calendar"
              />
            </VCardText>
          </VCard>
        </VCol>

        <!-- Notification Settings -->
        <VCol cols="12">
          <VCard elevation="2">
            <VCardTitle>Notification Settings</VCardTitle>
            <VCardText>
              <VRow>
                <VCol cols="12" md="4">
                  <VCheckbox
                    v-model="form.notifications.email"
                    label="Email Notifications"
                    color="primary"
                  />
                  <VCheckbox
                    v-model="form.notifications.push"
                    label="Push Notifications"
                    color="primary"
                  />
                </VCol>
                <VCol cols="12" md="4">
                  <VCheckbox
                    v-model="form.notifications.marketing"
                    label="Marketing Updates"
                    color="primary"
                  />
                  <VCheckbox
                    v-model="form.notifications.security"
                    label="Security Alerts"
                    color="primary"
                  />
                </VCol>
                <VCol cols="12" md="4">
                  <VCheckbox
                    v-model="form.notifications.newsletter"
                    label="Newsletter"
                    color="primary"
                  />
                  <VCheckbox
                    v-model="form.notifications.product_updates"
                    label="Product Updates"
                    color="primary"
                  />
                </VCol>
              </VRow>
            </VCardText>
          </VCard>
        </VCol>
      </VRow>

      <!-- Action Buttons -->
      <div class="d-flex justify-end mt-6 gap-4">
        <VBtn
          :to="{ name: 'profile' }"
          variant="outlined"
          size="large"
          :disabled="isLoading"
        >
          Cancel
        </VBtn>
        <VBtn
          type="submit"
          color="primary"
          size="large"
          :loading="isLoading"
          :disabled="!isFormValid || !hasChanges"
        >
          Save Changes
        </VBtn>
      </div>
    </VForm>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore, useUIStore } from '@/stores'
import type { User } from '@/types'

// Store references
const authStore = useAuthStore()
const uiStore = useUIStore()
const router = useRouter()

// Template refs
const formRef = ref()
const fileInput = ref<HTMLInputElement>()

// Component state
const isFormValid = ref(false)
const isLoading = ref(false)
const avatarPreview = ref<string | null>(null)
const avatarFile = ref<File | null>(null)
const formErrors = ref<Record<string, string[]>>({})
const originalForm = ref<any>(null)

// Form data
const form = reactive({
  first_name: '',
  last_name: '',
  email: '',
  phone: '',
  department: '',
  timezone: 'UTC',
  language: 'en',
  date_format: 'MM/DD/YYYY',
  notifications: {
    email: true,
    push: true,
    marketing: false,
    security: true,
    newsletter: false,
    product_updates: true
  }
})

// Options for select fields
const timezoneOptions = [
  { label: 'UTC', value: 'UTC' },
  { label: 'Eastern Time (ET)', value: 'America/New_York' },
  { label: 'Central Time (CT)', value: 'America/Chicago' },
  { label: 'Mountain Time (MT)', value: 'America/Denver' },
  { label: 'Pacific Time (PT)', value: 'America/Los_Angeles' },
  { label: 'Central European Time (CET)', value: 'Europe/Berlin' },
  { label: 'Greenwich Mean Time (GMT)', value: 'Europe/London' }
]

const languageOptions = [
  { label: 'English', value: 'en' },
  { label: 'Spanish', value: 'es' },
  { label: 'French', value: 'fr' },
  { label: 'German', value: 'de' },
  { label: 'Italian', value: 'it' },
  { label: 'Portuguese', value: 'pt' },
  { label: 'Japanese', value: 'ja' },
  { label: 'Korean', value: 'ko' },
  { label: 'Chinese (Simplified)', value: 'zh-CN' }
]

const dateFormatOptions = [
  { label: 'MM/DD/YYYY', value: 'MM/DD/YYYY' },
  { label: 'DD/MM/YYYY', value: 'DD/MM/YYYY' },
  { label: 'YYYY-MM-DD', value: 'YYYY-MM-DD' },
  { label: 'DD MMM YYYY', value: 'DD MMM YYYY' }
]

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

const phoneRules = [
  (v: string) => !v || /^[\+]?[1-9][\d]{0,15}$/.test(v) || 'Please enter a valid phone number'
]

const departmentRules = [
  (v: string) => !v || (v.length <= 100) || 'Department must be less than 100 characters'
]

// Computed properties
const user = computed(() => authStore.user)

const hasChanges = computed(() => {
  if (!originalForm.value) return false
  
  return JSON.stringify(form) !== JSON.stringify(originalForm.value) || 
         avatarFile.value !== null
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
 * Initialize form with user data
 */
function initializeForm() {
  if (!user.value) return

  Object.assign(form, {
    first_name: user.value.first_name || '',
    last_name: user.value.last_name || '',
    email: user.value.email || '',
    phone: user.value.phone || '',
    department: user.value.department || '',
    timezone: user.value.timezone || 'UTC',
    language: user.value.language || 'en',
    date_format: user.value.date_format || 'MM/DD/YYYY',
    notifications: {
      email: user.value.notifications?.email ?? true,
      push: user.value.notifications?.push ?? true,
      marketing: user.value.notifications?.marketing ?? false,
      security: user.value.notifications?.security ?? true,
      newsletter: user.value.notifications?.newsletter ?? false,
      product_updates: user.value.notifications?.product_updates ?? true
    }
  })

  // Store original form state for change detection
  originalForm.value = JSON.parse(JSON.stringify(form))
}

/**
 * Trigger file input click
 */
function triggerFileInput() {
  fileInput.value?.click()
}

/**
 * Handle file selection for avatar upload
 * 
 * @param event - File input change event
 */
function handleFileSelect(event: Event) {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]

  if (!file) return

  // Validate file type
  if (!file.type.startsWith('image/')) {
    uiStore.showError('Please select a valid image file.')
    return
  }

  // Validate file size (5MB limit)
  if (file.size > 5 * 1024 * 1024) {
    uiStore.showError('File size must be less than 5MB.')
    return
  }

  avatarFile.value = file

  // Create preview
  const reader = new FileReader()
  reader.onload = (e) => {
    avatarPreview.value = e.target?.result as string
  }
  reader.readAsDataURL(file)
}

/**
 * Remove avatar
 */
function removeAvatar() {
  avatarFile.value = null
  avatarPreview.value = null
  
  // Reset file input
  if (fileInput.value) {
    fileInput.value.value = ''
  }
}

/**
 * Handle form submission
 */
async function handleSubmit() {
  if (!isFormValid.value) return

  try {
    isLoading.value = true
    clearErrors()

    // Prepare form data
    const updateData = { ...form }

    // Handle avatar upload if file is selected
    if (avatarFile.value) {
      // In a real app, you would upload the file to a storage service
      // and get back a URL to save in the user profile
      console.log('Avatar file to upload:', avatarFile.value)
      // For now, we'll just use the preview URL
      // updateData.avatar_url = avatarPreview.value
    }

    // Update profile
    await authStore.updateProfile(updateData)

    // Show success message
    uiStore.showSuccess('Profile updated successfully!')

    // Update original form state
    originalForm.value = JSON.parse(JSON.stringify(form))
    avatarFile.value = null

    // Navigate back to profile
    router.push({ name: 'profile' })

  } catch (error: any) {
    console.error('Profile update failed:', error)

    // Handle validation errors
    if (error.details && typeof error.details === 'object') {
      formErrors.value = error.details
    } else {
      // Show general error message
      uiStore.showError(error.message || 'Failed to update profile. Please try again.')
    }

  } finally {
    isLoading.value = false
  }
}

/**
 * Load user profile data
 */
async function loadProfile() {
  try {
    await authStore.fetchCurrentUser()
    initializeForm()
  } catch (error: any) {
    console.error('Failed to load profile:', error)
    uiStore.showError('Failed to load profile data.')
  }
}

// Watchers
watch(user, (newUser) => {
  if (newUser) {
    initializeForm()
  }
}, { immediate: true })

// Lifecycle hooks
onMounted(() => {
  if (!user.value) {
    loadProfile()
  } else {
    initializeForm()
  }
})
</script>

<style scoped>
.edit-profile-view {
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px;
}

.v-card {
  border-radius: 16px;
}

.v-card-title {
  padding-bottom: 8px;
  font-weight: 600;
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
  margin-bottom: 8px;
}

.v-checkbox :deep(.v-selection-control__wrapper) {
  margin-right: 8px;
}

/* Avatar section styling */
.v-avatar {
  border: 3px solid rgba(var(--v-theme-primary), 0.1);
  transition: all 0.3s ease;
}

.v-avatar:hover {
  border-color: rgba(var(--v-theme-primary), 0.3);
  transform: scale(1.02);
}

/* Form layout adjustments */
.v-row {
  margin: 0;
}

.v-col {
  padding: 0 8px;
}

.v-col:first-child {
  padding-left: 0;
}

.v-col:last-child {
  padding-right: 0;
}

/* Action buttons */
.gap-4 {
  gap: 16px;
}

/* Focus states for accessibility */
.v-text-field:focus-within,
.v-select:focus-within {
  transform: translateY(-1px);
  transition: transform 0.2s ease;
}

/* Error state animation */
.v-text-field--error :deep(.v-field),
.v-select--error :deep(.v-field) {
  animation: shake 0.5s ease-in-out;
}

@keyframes shake {
  0%, 100% { transform: translateX(0); }
  25% { transform: translateX(-4px); }
  75% { transform: translateX(4px); }
}

/* Responsive adjustments */
@media (max-width: 960px) {
  .edit-profile-view {
    padding: 16px;
  }
}

@media (max-width: 600px) {
  .v-card-text {
    padding: 16px;
  }
  
  .d-flex.justify-end {
    flex-direction: column;
  }
  
  .gap-4 {
    gap: 12px;
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
