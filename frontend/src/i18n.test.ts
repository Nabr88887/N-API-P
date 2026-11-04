import { afterEach, describe, expect, it } from 'vitest'

import { setLocale, t } from './i18n'

afterEach(() => {
  setLocale('en')
})

describe('i18n', () => {
  it('translates known interface copy for Simplified Chinese', () => {
    setLocale('zh-CN')

    expect(t('Sign in')).toBe('登录')
    expect(t('Gateway operational')).toBe('网关运行正常')
    expect(t('Audit persistence unavailable')).toBe('审计持久化不可用')
  })

  it('translates operational recovery and security event codes', () => {
    setLocale('zh-CN')

    expect(t('Recovered')).toBe('已恢复')
    expect(t('Critical')).toBe('严重')
    expect(t('open')).toBe('进行中')
    expect(t('closed')).toBe('已关闭')

    const eventTypes = [
      'activation_completed', 'administrator_bootstrapped', 'audit_batch_view', 'audit_export_start',
      'audit_export_terminal', 'audit_grant_issued', 'audit_grant_revoked', 'audit_query',
      'credential_compromise_recovery', 'email_change', 'employee_disabled',
      'gateway_authentication_rejected', 'gateway_model_policy_rejected',
      'gateway_request_size_rejected', 'gateway_traffic_limit_rejected', 'investigation_access_grant',
      'investigation_case', 'investigation_case_raw_view', 'invitation_issued', 'login_lockout',
      'model_allowlist_change', 'password_reset_completed', 'password_reset_issued', 'raw_view',
      'retention_policy_change', 'role_change',
      'service_account_created', 'service_account_disabled', 'team_change', 'team_created',
      'team_disabled', 'team_updated',
    ]

    for (const eventType of eventTypes) {
      expect(t(eventType), eventType).not.toBe(eventType)
    }
    expect(t('denied')).toBe('已拒绝')
    expect(t('failure')).toBe('失败')
  })

  it('falls back to English copy and interpolates values', () => {
    setLocale('zh-CN')

    expect(t('Revoke {name}', { name: 'workstation' })).toBe('撤销 workstation')
    expect(t('Untranslated copy')).toBe('Untranslated copy')
  })
})
