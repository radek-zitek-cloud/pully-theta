/**
 * Vuetify Plugin Configuration
 * 
 * Configures Vuetify 3 with custom theme, Material Design Icons,
 * and responsive breakpoints for the application.
 */

import { createVuetify } from 'vuetify'
import { aliases, mdi } from 'vuetify/iconsets/mdi'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

// Import Vuetify styles
import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css'

/**
 * Custom theme configuration
 * 
 * Defines light and dark theme colors following Material Design 3 principles.
 * Colors are chosen for accessibility and brand consistency.
 */
const customTheme = {
  light: {
    dark: false,
    colors: {
      primary: '#1976D2',        // Blue 700
      secondary: '#424242',      // Gray 800
      accent: '#FF4081',         // Pink A200
      error: '#F44336',          // Red 500
      warning: '#FF9800',        // Orange 500
      info: '#2196F3',           // Blue 500
      success: '#4CAF50',        // Green 500
      background: '#FAFAFA',     // Gray 50
      surface: '#FFFFFF',        // White
      'on-primary': '#FFFFFF',
      'on-secondary': '#FFFFFF',
      'on-accent': '#FFFFFF',
      'on-error': '#FFFFFF',
      'on-warning': '#000000',
      'on-info': '#FFFFFF',
      'on-success': '#FFFFFF',
      'on-background': '#212121',
      'on-surface': '#212121'
    }
  },
  dark: {
    dark: true,
    colors: {
      primary: '#2196F3',        // Blue 500
      secondary: '#616161',      // Gray 600
      accent: '#FF4081',         // Pink A200
      error: '#F44336',          // Red 500
      warning: '#FFC107',        // Amber 500
      info: '#03DAC6',           // Teal A400
      success: '#4CAF50',        // Green 500
      background: '#121212',     // Material Dark Background
      surface: '#1E1E1E',        // Material Dark Surface
      'on-primary': '#FFFFFF',
      'on-secondary': '#FFFFFF',
      'on-accent': '#000000',
      'on-error': '#FFFFFF',
      'on-warning': '#000000',
      'on-info': '#000000',
      'on-success': '#FFFFFF',
      'on-background': '#FFFFFF',
      'on-surface': '#FFFFFF'
    }
  }
}

/**
 * Custom breakpoints for responsive design
 * 
 * Defines screen size breakpoints for consistent responsive behavior
 * across the application components.
 */
const customBreakpoints = {
  thresholds: {
    xs: 0,       // Extra small devices (phones)
    sm: 600,     // Small devices (tablets)
    md: 960,     // Medium devices (small laptops)
    lg: 1280,    // Large devices (desktops)
    xl: 1920,    // Extra large devices (large desktops)
    xxl: 2560    // Extra extra large devices
  }
}

/**
 * Vuetify configuration object
 * 
 * Configures all aspects of Vuetify including theme, icons,
 * components, directives, and display settings.
 */
export default createVuetify({
  // Component registration
  components,
  directives,
  
  // Theme configuration
  theme: {
    defaultTheme: 'light',
    themes: customTheme,
    variations: {
      colors: ['primary', 'secondary', 'accent'],
      lighten: 5,
      darken: 5
    }
  },
  
  // Icon configuration
  icons: {
    defaultSet: 'mdi',
    aliases,
    sets: {
      mdi
    }
  },
  
  // Display/responsive configuration
  display: {
    mobileBreakpoint: 'md',
    thresholds: customBreakpoints.thresholds
  },
  
  // Default component props
  defaults: {
    // Button defaults
    VBtn: {
      elevation: 1,
      variant: 'flat'
    },
    
    // Card defaults
    VCard: {
      elevation: 2,
      variant: 'flat'
    },
    
    // Text field defaults
    VTextField: {
      variant: 'outlined',
      density: 'comfortable'
    },
    
    // Select defaults
    VSelect: {
      variant: 'outlined',
      density: 'comfortable'
    },
    
    // Autocomplete defaults
    VAutocomplete: {
      variant: 'outlined',
      density: 'comfortable'
    },
    
    // Textarea defaults
    VTextarea: {
      variant: 'outlined',
      density: 'comfortable'
    },
    
    // App bar defaults
    VAppBar: {
      elevation: 1
    },
    
    // Navigation drawer defaults
    VNavigationDrawer: {
      elevation: 2
    },
    
    // Dialog defaults
    VDialog: {
      maxWidth: 500
    },
    
    // Snackbar defaults
    VSnackbar: {
      timeout: 5000,
      location: 'bottom right'
    }
  },
  
  // Locale configuration
  locale: {
    locale: 'en',
    fallback: 'en'
  }
})
