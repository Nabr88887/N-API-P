import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page, type TestInfo } from '@playwright/test'

type Role = 'employee' | 'team_administrator' | 'system_administrator'

const browserErrors = new WeakMap<Page, string[]>()

test.beforeEach(async ({ page }) => {
  const errors: string[] = []
  browserErrors.set(page, errors)
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(`console: ${message.text()}`)
  })
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`))
})

test.afterEach(async ({ page }) => {
  expect(browserErrors.get(page)).toEqual([])
})

async function capture(page: Page, testInfo: TestInfo, name: string) {
  await assertLayout(page)
  await assertAccessible(page)
  const path = testInfo.outputPath(`${name}.png`)
  await page.screenshot({ path, fullPage: true })
  await testInfo.attach(name, { path, contentType: 'image/png' })
}

async function assertAccessible(page: Page) {
  const result = await new AxeBuilder({ page }).analyze()
  const violations = result.violations.map((violation) => {
    const targets = violation.nodes.flatMap((node) => node.target).join(', ')
    return `${violation.id}: ${targets}`
  })
  expect(violations).toEqual([])
}

async function assertLayout(page: Page) {
  const dimensions = await page.evaluate(() => {
    const overflowingDialogs = Array.from(document.querySelectorAll<HTMLElement>('[role="dialog"]'))
      .map((dialog) => {
        const bounds = dialog.getBoundingClientRect()
        return { name: dialog.getAttribute('aria-labelledby') ?? 'unlabelled', bounds }
      })
      .filter(({ bounds }) => bounds.width > 0 && bounds.height > 0 && (
        bounds.left < 0 || bounds.top < 0 || bounds.right > window.innerWidth || bounds.bottom > window.innerHeight
      ))
      .map(({ name }) => name)
    return { bodyWidth: document.body.scrollWidth, viewportWidth: window.innerWidth, overflowingDialogs }
  })
  expect(dimensions.bodyWidth).toBeLessThanOrEqual(dimensions.viewportWidth)
  expect(dimensions.overflowingDialogs).toEqual([])
}

async function openRole(page: Page, role: Role, fault = '') {
  const query = new URLSearchParams({ role })
  if (fault) query.set('fault', fault)
  await page.goto(`/e2e/harness.html?${query.toString()}`)
  await expect(page.getByRole('main', { name: 'Administration workspace' })).toBeVisible()
  await assertLayout(page)
}

async function navigate(page: Page, name: string) {
  const navigationTrigger = page.getByRole('button', { name: 'Open navigation' })
  if (await navigationTrigger.isVisible()) {
    await navigationTrigger.click()
    await expect(page.getByTitle('Close navigation')).toBeFocused()
  }
  await page.getByRole('link', { name }).click()
  await expect(page.getByRole('main', { name: 'Administration workspace' })).toBeFocused()
}

for (const role of ['employee', 'team_administrator', 'system_administrator'] as const) {
  test(`${role} overview is accessible and bounded`, async ({ page }, testInfo) => {
    await openRole(page, role)
    await page.keyboard.press('Tab')
    const skipLink = page.getByRole('link', { name: 'Skip to main content' })
    await expect(skipLink).toBeFocused()
    await skipLink.press('Enter')
    await expect(page.getByRole('main', { name: 'Administration workspace' })).toBeFocused()
    await expect(skipLink).not.toBeInViewport()
    await capture(page, testInfo, `${role}-overview`)

    const navigationTrigger = page.getByRole('button', { name: 'Open navigation' })
    if (await navigationTrigger.isVisible()) {
      await navigationTrigger.click()
      const closeNavigation = page.getByTitle('Close navigation')
      await expect(closeNavigation).toBeFocused()
      await page.keyboard.press('Shift+Tab')
      await expect(page.getByRole('link', { name: 'Support' })).toBeFocused()
      await page.keyboard.press('Tab')
      await expect(closeNavigation).toBeFocused()
      await page.keyboard.press('Escape')
      await expect(navigationTrigger).toBeFocused()
    }
  })
}

test('employee sensitive key workflow is keyboard reachable and bounded', async ({ page }, testInfo) => {
  await openRole(page, 'employee')
  await navigate(page, 'My keys')
  await expect(page.getByRole('table', { name: 'Personal API keys' })).toBeVisible()
  await capture(page, testInfo, 'employee-keys')

  const createKeyButton = page.getByRole('button', { name: 'Create personal key' })
  await createKeyButton.click()
  const dialog = page.getByRole('dialog', { name: 'Create personal key' })
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText('Create personal key')
  await expect(dialog).toBeFocused()
  await page.keyboard.press('Shift+Tab')
  await expect(dialog.getByRole('button', { name: 'Create key', exact: true })).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(dialog.getByRole('button', { name: 'Close create key' })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(dialog).not.toBeVisible()
  await expect(createKeyButton).toBeFocused()
  await createKeyButton.click()
  await expect(dialog).toBeFocused()
  await capture(page, testInfo, 'employee-create-key-dialog')
  await dialog.getByRole('textbox', { name: 'Key name' }).fill('mobile-review')
  await dialog.getByRole('button', { name: 'Create key', exact: true }).click()
  await expect(page.getByRole('dialog', { name: 'New personal key' })).toBeVisible()
  await capture(page, testInfo, 'employee-issued-key-dialog')
  await page.getByRole('button', { name: 'I have saved this key' }).click()
  await page.getByRole('button', { name: 'Revoke workstation' }).click()
  await expect(page.getByRole('dialog', { name: 'Revoke personal key' })).toBeVisible()
  await capture(page, testInfo, 'employee-revoke-key-dialog')
})

test('team administrator member and usage views remain accessible', async ({ page }, testInfo) => {
  await openRole(page, 'team_administrator')
  await navigate(page, 'Team members')
  await expect(page.getByRole('table', { name: 'Team members' })).toBeVisible()
  await capture(page, testInfo, 'team-members')
  await navigate(page, 'Team usage')
  await expect(page.getByRole('table', { name: 'Team usage records' })).toBeVisible()
  await capture(page, testInfo, 'team-usage')
})

test('system administrator sensitive workflows preserve permissions and focus', async ({ page }, testInfo) => {
  await openRole(page, 'system_administrator', 'audit_unavailable')
  await expect(page.getByRole('alert', { name: 'Audit persistence unavailable' })).toBeVisible()
  await capture(page, testInfo, 'system-overview-critical-fault')

  await navigate(page, 'People & teams')
  await expect(page.getByRole('table', { name: 'Accounts' })).toBeVisible()
  await page.getByRole('button', { name: 'Invite employee' }).click()
  const invite = page.getByRole('dialog', { name: 'Invite employee' })
  await expect(invite).toBeFocused()
  await invite.getByRole('textbox', { name: 'Company email' }).fill('new.employee@company.internal')
  await capture(page, testInfo, 'system-invite-dialog')
  await invite.getByRole('button', { name: 'Create invitation' }).click()
  const invitationCredential = page.getByRole('dialog', { name: 'New invitation' })
  await expect(invitationCredential).toBeFocused()
  await capture(page, testInfo, 'system-invitation-credential')
  await invitationCredential.getByRole('button', { name: 'I have saved this value' }).click()
  await expect(page.getByRole('button', { name: 'Invite employee' })).toBeFocused()

  const accessButton = page.getByRole('button', { name: 'Manage access for employee@company.internal' })
  await accessButton.click()
  const access = page.getByRole('dialog', { name: 'Manage access' })
  await expect(access).toBeFocused()
  await capture(page, testInfo, 'system-access-dialog')
  await access.getByRole('button', { name: 'Apply role' }).click()
  const roleConfirmation = page.getByRole('dialog', { name: 'Confirm role change' })
  await expect(roleConfirmation).toBeFocused()
  await capture(page, testInfo, 'system-role-confirmation')
  await roleConfirmation.getByRole('button', { name: 'Cancel' }).click()
  await access.getByRole('button', { name: 'Close' }).click()
  await expect(accessButton).toBeFocused()

  const recoveryButton = page.getByRole('button', { name: 'Recover employee@company.internal' })
  await recoveryButton.click()
  const recovery = page.getByRole('dialog', { name: 'Assisted password recovery' })
  await expect(recovery).toBeFocused()
  await capture(page, testInfo, 'system-recovery-dialog')
  await recovery.getByRole('checkbox', { name: 'Manual identity verification completed' }).check()
  await recovery.getByRole('button', { name: 'Issue reset value' }).click()
  const resetCredential = page.getByRole('dialog', { name: 'New password reset value' })
  await expect(resetCredential).toBeFocused()
  await capture(page, testInfo, 'system-reset-credential')
  await resetCredential.getByRole('button', { name: 'I have saved this value' }).click()
  await expect(recoveryButton).toBeFocused()

  await navigate(page, 'Service accounts')
  await expect(page.getByRole('table', { name: 'Service accounts' })).toBeVisible()
  await page.getByRole('button', { name: 'Create service account' }).click()
  await expect(page.getByRole('dialog', { name: 'Create service account' })).toBeVisible()
  await capture(page, testInfo, 'system-service-account-dialog')
  await page.getByRole('button', { name: 'Cancel' }).click()

  await page.getByRole('button', { name: 'Manage keys for ci-agent' }).click()
  const groupKeys = page.getByRole('dialog', { name: 'Group keys' })
  await expect(groupKeys).toBeFocused()
  await capture(page, testInfo, 'system-group-keys-dialog')
  await groupKeys.getByRole('button', { name: 'Create group key' }).click()
  const groupKeyCreate = page.getByRole('dialog', { name: 'Create group key' })
  await expect(groupKeyCreate).toBeFocused()
  await capture(page, testInfo, 'system-group-key-create-dialog')
  await groupKeyCreate.getByRole('textbox', { name: 'Group key name' }).fill('automation')
  await groupKeyCreate.getByRole('button', { name: 'Create key' }).click()
  const groupCredential = page.getByRole('dialog', { name: 'New group key' })
  await expect(groupCredential).toBeFocused()
  await capture(page, testInfo, 'system-group-key-credential')
  await groupCredential.getByRole('button', { name: 'I have saved this value' }).click()
  await expect(groupKeys.getByRole('button', { name: 'Create group key' })).toBeFocused()

  await groupKeys.getByRole('button', { name: 'Rotate' }).first().click()
  const rotate = page.getByRole('dialog', { name: 'Rotate group key' })
  await expect(rotate).toBeFocused()
  await capture(page, testInfo, 'system-group-key-rotate-dialog')
  await rotate.getByRole('button', { name: 'Confirm rotation' }).click()
  const rotatedCredential = page.getByRole('dialog', { name: 'New group key' })
  await expect(rotatedCredential).toBeFocused()
  await capture(page, testInfo, 'system-rotated-key-credential')
  await rotatedCredential.getByRole('button', { name: 'I have saved this value' }).click()

  await groupKeys.getByRole('button', { name: 'Revoke' }).first().click()
  const revokeGroupKey = page.getByRole('dialog', { name: 'Revoke group key' })
  await expect(revokeGroupKey).toBeFocused()
  await capture(page, testInfo, 'system-group-key-revoke-confirmation')
  await revokeGroupKey.getByRole('button', { name: 'Cancel' }).click()
  await groupKeys.getByRole('button', { name: 'Close' }).click()

  await page.getByRole('button', { name: 'Disable ci-agent' }).click()
  const disableService = page.getByRole('dialog', { name: 'Disable service account' })
  await expect(disableService).toBeFocused()
  await capture(page, testInfo, 'system-service-account-disable-confirmation')
  await disableService.getByRole('button', { name: 'Cancel' }).click()

  await navigate(page, 'Model policy')
  await expect(page.getByRole('table', { name: 'Global model allowlist' })).toBeVisible()
  await page.getByRole('button', { name: 'Save model policy' }).click()
  const modelConfirmation = page.getByRole('dialog', { name: 'Confirm model policy' })
  await expect(modelConfirmation).toBeFocused()
  await capture(page, testInfo, 'system-model-confirmation')
  await modelConfirmation.getByRole('button', { name: 'Confirm model policy change' }).click()
  const reauthentication = page.getByRole('dialog', { name: 'Reauthenticate' })
  await expect(reauthentication).toBeFocused()
  await capture(page, testInfo, 'system-reauthentication-dialog')
  await reauthentication.getByLabel('Current password').fill('synthetic-current-password')
  await reauthentication.getByRole('button', { name: 'Reauthenticate and continue' }).click()
  await expect(reauthentication).not.toBeVisible()

  await navigate(page, 'Retention')
  await expect(page.getByRole('spinbutton', { name: 'Raw content retention days' })).toBeVisible()
  await page.getByRole('button', { name: 'Save retention policy' }).click()
  await expect(page.getByRole('dialog', { name: 'Confirm retention change' })).toBeVisible()
  await capture(page, testInfo, 'system-retention-confirmation')
  await page.getByRole('button', { name: 'Cancel' }).click()

  await navigate(page, 'Audit')
  await expect(page.getByRole('table', { name: 'Audit metadata' })).toBeVisible()
  await page.getByRole('button', { name: /Inspect raw content/ }).click()
  const inspection = page.getByRole('dialog', { name: 'Inspect one audit record' })
  await expect(inspection).toBeFocused()
  await inspection.getByRole('textbox', { name: 'Investigation reason' }).fill('Synthetic accessibility review')
  await capture(page, testInfo, 'system-audit-inspection-dialog')
  await inspection.getByRole('button', { name: 'Inspect one record' }).click()
  const rawAudit = page.getByRole('dialog', { name: 'Raw audit record' })
  await expect(rawAudit).toBeVisible()
  await capture(page, testInfo, 'system-raw-audit-dialog')
  await rawAudit.press('Escape')
  await expect(rawAudit).not.toBeVisible()

  await navigate(page, 'Operations')
  await expect(page.getByRole('table', { name: 'Recent operational events' })).toBeVisible()
  await capture(page, testInfo, 'system-operations')
})
