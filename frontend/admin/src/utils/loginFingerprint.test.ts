import { afterEach, describe, expect, it } from 'vitest'
import { isAdminLoginFingerprintPath, loginFingerprint, resetLoginFingerprintCache } from './loginFingerprint'

afterEach(() => {
  resetLoginFingerprintCache()
})

describe('isAdminLoginFingerprintPath', () => {
  it('attaches only to the two admin login requests', () => {
    expect(isAdminLoginFingerprintPath('/admin/login')).toBe(true)
    expect(isAdminLoginFingerprintPath('/admin/login/verify-2fa')).toBe(true)
    expect(isAdminLoginFingerprintPath('/admin/login-logs')).toBe(false)
    expect(isAdminLoginFingerprintPath('/admin/admin-login-logs')).toBe(false)
    expect(isAdminLoginFingerprintPath('/login')).toBe(false)
  })
})

describe('loginFingerprint', () => {
  it('returns a stable 64-char hex digest', async () => {
    const first = await loginFingerprint()
    const second = await loginFingerprint()
    expect(first).toMatch(/^[0-9a-f]{64}$/)
    expect(second).toBe(first)
  })
})
