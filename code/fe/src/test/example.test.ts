/**
 * Example component test to verify Vitest configuration
 * 
 * This test demonstrates basic Vue component testing setup
 * with our configured testing environment.
 */

import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'

// Simple test component
const TestComponent = {
  template: '<div class="test-component">Hello Test</div>',
  props: {
    message: {
      type: String,
      default: 'Hello Test'
    }
  }
}

describe('Test Configuration', () => {
  it('should mount Vue components correctly', () => {
    const wrapper = mount(TestComponent)

    expect(wrapper.text()).toBe('Hello Test')
    expect(wrapper.vm).toBeTruthy()
    expect(wrapper.classes()).toContain('test-component')
  })

  it('should handle component props correctly', () => {
    const wrapper = mount(TestComponent, {
      props: {
        message: 'Custom Message'
      }
    })

    expect(wrapper.text()).toBe('Hello Test') // Template has static text
    expect(wrapper.props('message')).toBe('Custom Message')
  })

  it('should have access to global test utilities', () => {
    expect(typeof (globalThis as any).testUtils).toBe('object')
    expect(typeof (globalThis as any).testUtils.delay).toBe('function')
    expect(typeof (globalThis as any).testUtils.createMockUser).toBe('function')
    expect(typeof (globalThis as any).testUtils.createMockTokens).toBe('function')
  })

  it('should create mock user correctly', () => {
    const mockUser = (globalThis as any).testUtils.createMockUser()
    
    expect(mockUser).toHaveProperty('id')
    expect(mockUser).toHaveProperty('username')
    expect(mockUser).toHaveProperty('email')
    expect(mockUser).toHaveProperty('first_name')
    expect(mockUser).toHaveProperty('last_name')
    expect(mockUser).toHaveProperty('is_email_verified')
    expect(mockUser.email).toBe('test@example.com')
    expect(mockUser.username).toBe('testuser')
  })

  it('should create mock tokens correctly', () => {
    const mockTokens = (globalThis as any).testUtils.createMockTokens()
    
    expect(mockTokens).toHaveProperty('access_token')
    expect(mockTokens).toHaveProperty('refresh_token')
    expect(mockTokens).toHaveProperty('expires_in')
    expect(mockTokens).toHaveProperty('token_type')
    expect(mockTokens.token_type).toBe('Bearer')
    expect(mockTokens.expires_in).toBe(3600)
  })

  it('should handle async operations', async () => {
    const delay = (globalThis as any).testUtils.delay
    const start = Date.now()
    
    await delay(50)
    
    const end = Date.now()
    expect(end - start).toBeGreaterThanOrEqual(45) // Allow some margin
  })
})
