/**
 * Confirmation Dialog Component
 * 
 * Global confirmation dialog for destructive actions and important decisions.
 * Provides consistent UX for user confirmations across the application.
 */

<template>
  <VDialog
    v-model="dialogVisible"
    :max-width="maxWidth"
    persistent
    @keydown.esc="handleCancel"
  >
    <VCard v-if="uiStore.confirmDialog">
      <!-- Dialog Header -->
      <VCardTitle class="d-flex align-center">
        <VIcon
          :icon="dialogIcon"
          :color="dialogIconColor"
          class="mr-3"
          size="24"
        />
        <span>{{ uiStore.confirmDialog.title }}</span>
      </VCardTitle>

      <!-- Dialog Content -->
      <VCardText>
        <div class="dialog-message">
          {{ uiStore.confirmDialog.message }}
        </div>
        
        <!-- Warning for destructive actions -->
        <VAlert
          v-if="uiStore.confirmDialog.destructive"
          type="warning"
          variant="tonal"
          class="mt-4"
          density="compact"
        >
          <template #prepend>
            <VIcon>mdi-alert-triangle</VIcon>
          </template>
          This action cannot be undone.
        </VAlert>
      </VCardText>

      <!-- Dialog Actions -->
      <VCardActions class="justify-end pa-4">
        <VBtn
          variant="text"
          @click="handleCancel"
          :disabled="isProcessing"
        >
          {{ uiStore.confirmDialog.cancelText }}
        </VBtn>
        
        <VBtn
          :color="uiStore.confirmDialog.confirmColor"
          :variant="uiStore.confirmDialog.destructive ? 'elevated' : 'flat'"
          :loading="isProcessing"
          @click="handleConfirm"
        >
          {{ uiStore.confirmDialog.confirmText }}
        </VBtn>
      </VCardActions>
    </VCard>
  </VDialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useUIStore } from '@/stores'

// Store reference
const uiStore = useUIStore()

// Local state
const isProcessing = ref(false)

// Props
interface Props {
  maxWidth?: string | number
}

const props = withDefaults(defineProps<Props>(), {
  maxWidth: 500
})

// Computed properties
const dialogVisible = computed({
  get: () => Boolean(uiStore.confirmDialog?.visible),
  set: (value: boolean) => {
    if (!value && uiStore.confirmDialog) {
      handleCancel()
    }
  }
})

const dialogIcon = computed(() => {
  if (!uiStore.confirmDialog) return 'mdi-help-circle'
  
  if (uiStore.confirmDialog.destructive) {
    return 'mdi-alert-circle-outline'
  }
  
  return 'mdi-help-circle-outline'
})

const dialogIconColor = computed(() => {
  if (!uiStore.confirmDialog) return 'primary'
  
  if (uiStore.confirmDialog.destructive) {
    return 'error'
  }
  
  return 'primary'
})

// Methods

/**
 * Handle confirm button click
 */
async function handleConfirm() {
  if (!uiStore.confirmDialog) return
  
  try {
    isProcessing.value = true
    
    // Execute the confirm callback
    const result = uiStore.confirmDialog.onConfirm()
    
    // Handle async callbacks
    if (result instanceof Promise) {
      await result
    }
    
  } catch (error) {
    console.error('Error in confirmation callback:', error)
    uiStore.showError('An error occurred while processing your request.')
  } finally {
    isProcessing.value = false
    uiStore.hideConfirmDialog()
  }
}

/**
 * Handle cancel button click or escape key
 */
function handleCancel() {
  if (isProcessing.value) return
  
  if (uiStore.confirmDialog?.onCancel) {
    try {
      uiStore.confirmDialog.onCancel()
    } catch (error) {
      console.error('Error in cancel callback:', error)
    }
  }
  
  uiStore.hideConfirmDialog()
}

// Watch for dialog state changes
watch(
  () => uiStore.confirmDialog,
  (newDialog) => {
    if (newDialog) {
      isProcessing.value = false
    }
  }
)
</script>

<style scoped>
.dialog-message {
  font-size: 1rem;
  line-height: 1.5;
  white-space: pre-wrap;
  color: rgb(var(--v-theme-on-surface));
}

.v-card-title {
  font-size: 1.25rem;
  font-weight: 500;
  letter-spacing: 0.0125em;
  padding: 20px 24px 0;
}

.v-card-text {
  padding: 16px 24px;
}

.v-card-actions {
  padding: 8px 16px 16px;
}

/* Destructive action styling */
.v-btn[data-destructive="true"] {
  background-color: rgb(var(--v-theme-error)) !important;
  color: rgb(var(--v-theme-on-error)) !important;
}

.v-btn[data-destructive="true"]:hover {
  background-color: rgb(var(--v-theme-error-darken-1)) !important;
}

/* Focus management */
.v-dialog:focus-within {
  outline: none;
}

.v-card {
  overflow: visible;
}

/* Animation */
.v-dialog {
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

/* Responsive adjustments */
@media (max-width: 600px) {
  .v-card-title {
    font-size: 1.125rem;
    padding: 16px 20px 0;
  }
  
  .v-card-text {
    padding: 12px 20px;
  }
  
  .v-card-actions {
    padding: 8px 12px 12px;
    flex-direction: column-reverse;
    gap: 8px;
  }
  
  .v-card-actions .v-btn {
    width: 100%;
  }
  
  .dialog-message {
    font-size: 0.875rem;
  }
}
</style>
