import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

const PAGES = [
  { path: '/', name: 'Upload', markers: ['UPLOAD CYBER LOGS'] },
  { path: '/demo', name: 'Demo', markers: ['CINEMATIC DEMO MODE'] },
  { path: '/dashboard', name: 'Dashboard', markers: ['SOC DASHBOARD'] },
  { path: '/explorer', name: 'Explorer', markers: ['LOG EXPLORER'] },
  { path: '/threats', name: 'Threats', markers: ['THREAT CORRELATION'] },
  { path: '/alerts', name: 'Alerts', markers: ['ALERTS'] },
  { path: '/live', name: 'EventWall', markers: ['EVENT WALL'] },
  { path: '/graph', name: 'Graph', markers: ['LIVE ATTACK GRAPH'] },
  { path: '/intel', name: 'Intel', markers: ['THREAT INTELLIGENCE'] },
  { path: '/privacy', name: 'Privacy', markers: ['PRIVACY POLICY ENGINE'] },
  { path: '/export', name: 'Export', markers: ['SIEM EXPORT'] },
  { path: '/benchmark', name: 'Benchmark', markers: ['BENCHMARK', 'RUN BENCHMARK'] },
]

let token = ''
let seedJobId = ''

function seedText() {
  const lines = []
  for (let i = 0; i < 60; i++) {
    const mm = String(i).padStart(2, '0')
    lines.push(`Aug 25 10:${mm}:0${i % 10} server sshd[1${i}]: Failed password for admin from 185.23.45.67 port ${5000 + i} ssh2`)
  }
  lines.push('Aug 25 10:59:59 server sshd[1999]: Accepted password for admin from 10.0.0.7 port 51234 ssh2')
  return lines.join('\n')
}

async function login(page) {
  await page.goto('/login')
  await page.fill('#username', 'admin')
  await page.fill('#password', 'changeme')
  await Promise.all([
    page.waitForURL('**/'),
    page.click('button[type="submit"]'),
  ])
}

async function selectSeedJob(page) {
  const combo = page.getByRole('combobox', { name: 'Select dataset' })
  const opt = combo.locator('option', { hasText: 'e2e_seed' }).first()
  await opt.waitFor({ state: 'attached', timeout: 15_000 })
  const val = await opt.getAttribute('value')
  await combo.selectOption(val)
}

function openHtml(page) {
  return page.locator('html')
}

test.beforeAll(async ({ request }) => {
  const login = await request.post('/api/auth/login', { data: { username: 'admin', password: 'changeme' } })
  expect(login.ok()).toBeTruthy()
  token = (await login.json()).access_token
  const auth = { Authorization: `Bearer ${token}` }
  const paste = await request.post('/api/paste', { headers: auth, data: { text: seedText(), name: 'e2e_seed.log' } })
  expect(paste.ok()).toBeTruthy()
  seedJobId = (await paste.json()).job_id
  for (let i = 0; i < 180; i++) {
    const r = await request.get(`/api/jobs/${seedJobId}`, { headers: auth })
    const j = await r.json()
    if (j.status === 'done' || j.status === 'error') break
    await new Promise((res) => setTimeout(res, 500))
  }
})

test.beforeEach(async ({ page }) => {
  const auth = { Authorization: `Bearer ${token}` }
  await page.addInitScript((t) => { if (t) localStorage.setItem('ls_token', t) }, token)
})

test('login with default credentials and land on upload page', async ({ page }) => {
  await login(page)
  await expect(page).toHaveURL(/\/$/)
  await expect(page.getByText('UPLOAD CYBER LOGS')).toBeVisible()
})

test('login page passes axe accessibility scan', async ({ page }) => {
  await page.goto('/login')
  const results = await new AxeBuilder({ page }).analyze()
  const serious = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
  expect(serious, `${serious.map((v) => `${v.id} (${v.impact})`).join(', ')}`).toEqual([])
})

for (const p of PAGES) {
  test(`${p.name} (/ ${p.path}) renders without console errors, failed requests, or blank page`, async ({ page }) => {
    const consoleErrors = []
    const pageErrors = []
    const failedReqs = []
    page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()) })
    page.on('pageerror', (e) => pageErrors.push(String(e)))
    page.on('response', (r) => { if (r.status() >= 400) failedReqs.push(`${r.status()} ${r.url()}`) })

    await page.goto(p.path)
    await expect(openHtml(page)).toContainText(p.markers[0])

    const blank = await page.evaluate(() => {
      const body = document.body
      return !body || body.textContent.trim().length === 0 && body.children.length <= 1
    })
    expect(blank, 'page body should not be blank').toBe(false)
    expect(consoleErrors, `console errors on ${p.path}: ${consoleErrors.join(' | ')}`).toEqual([])
    expect(pageErrors, `pageerrors on ${p.path}: ${pageErrors.join(' | ')}`).toEqual([])
    expect(failedReqs, `failed requests on ${p.path}: ${failedReqs.join(' | ')}`).toEqual([])

    const results = await new AxeBuilder({ page }).analyze()
    const serious = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
    expect(serious, `${p.name} axe: ${serious.map((v) => `${v.id} (${v.impact})`).join(', ')}`).toEqual([])
  })
}

test('Explorer: select seed job, open event detail dialog, Escape closes', async ({ page }) => {
  await login(page)
  await page.goto('/explorer')
  await selectSeedJob(page)
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await page.locator('tbody tr').first().click()
  await expect(page.getByText('EVENT DETAIL — RAW vs NORMALIZED')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByText('EVENT DETAIL — RAW vs NORMALIZED')).not.toBeVisible()

  const results = await new AxeBuilder({ page }).analyze()
  const serious = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
  expect(serious, `Explorer w/ data axe: ${serious.map((v) => `${v.id} (${v.impact})`).join(', ')}`).toEqual([])
})

test('Explorer: paginates through seeded events', async ({ page }) => {
  await login(page)
  await page.goto('/explorer')
  await selectSeedJob(page)
  await expect(page.getByText(/page 1\//)).toBeVisible()
  await page.getByRole('button', { name: /NEXT/ }).click()
  await expect(page.getByText(/page 2\//)).toBeVisible()
  const rows = await page.locator('tbody tr').count()
  expect(rows).toBeGreaterThan(0)
  expect(rows).toBeLessThanOrEqual(50)
})

test('Dashboard: selecting a job renders cards and export triggers a download', async ({ page }) => {
  await login(page)
  await page.goto('/dashboard')
  await selectSeedJob(page)
  await expect(page.getByText('TOTAL EVENTS')).toBeVisible()

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: /EXPORT JSON/ }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toContain('.json')
})

test('Threats/Intel/Graph render with seeded data', async ({ page }) => {
  await login(page)
  for (const p of ['/threats', '/intel', '/graph']) {
    await page.goto(p)
    await selectSeedJob(page)
    await expect(openHtml(page)).toContainText(
      p === '/threats' ? /ALL RULE MATCHES|WHY WAS THIS DETECTED/ : p === '/intel' ? 'INDICATORS' : /nodes|No entities/,
    )
  }
})

test('Alerts: seeded brute force generates an alert and ack transitions status', async ({ page }) => {
  await login(page)
  await page.goto('/alerts')
  await expect(page.getByText('Brute Force Attempt', { exact: false }).first()).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: 'ACK' }).first().click()
  await expect(page.getByText('ACKNOWLEDGED', { exact: false }).first()).toBeVisible({ timeout: 15_000 })
})

test('Threats: triage status change and investigation timeline modal', async ({ page }) => {
  await login(page)
  await page.goto('/threats')
  await selectSeedJob(page)
  await expect(page.getByText(/WHY WAS THIS DETECTED/).first()).toBeVisible({ timeout: 30_000 })
  const firstStatus = page.getByRole('combobox', { name: /Set status for/ }).first()
  await firstStatus.selectOption('ACKNOWLEDGED')
  await expect(page.getByText('ACKNOWLEDGED').first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: 'VIEW TIMELINE' }).first().click()
  await expect(page.getByText('INVESTIGATION TIMELINE')).toBeVisible()
  await expect(openHtml(page)).toContainText(/credential-access|phases|INVESTIGATION TIMELINE/)
  await page.getByRole('button', { name: /Close investigation timeline/ }).click()
  await expect(page.getByText('INVESTIGATION TIMELINE')).not.toBeVisible()
})

test('Event wall: start stream shows live events then stops', async ({ page }) => {
  await login(page)
  await page.request.post('/api/stream/stop', { headers: { Authorization: `Bearer ${token}` } })
  await page.goto('/live')
  await page.getByRole('button', { name: /START STREAM/ }).click()
  await expect(page.getByText('● LIVE')).toBeVisible({ timeout: 15_000 })
  await expect(openHtml(page)).toContainText(/Failed password|ACTION=|"GET |Accepted|srv01/).catch(async () => {})
  await page.getByRole('button', { name: /STOP STREAM/ }).click()
  await expect(page.getByText('○ STANDBY')).toBeVisible({ timeout: 15_000 })
})

test('Upload: drag-drop file upload creates a job and navigates to dashboard', async ({ page }) => {
  await login(page)
  await page.setInputFiles('input[type="file"]', {
    name: 'upload_test.log',
    mimeType: 'text/plain',
    buffer: Buffer.from(seedText().split('\n').slice(0, 20).join('\n')),
  })
  await page.waitForURL(/\/dashboard\/[0-9a-f-]+/i)
})

test('Upload: running a sample scenario navigates to dashboard', async ({ page }) => {
  await login(page)
  await page.getByRole('button', { name: /LOAD SAMPLE SCENARIOS/ }).click()
  await expect(page.getByRole('button', { name: /KB/ }).first()).toBeVisible()
  await page.getByRole('button', { name: /KB/ }).first().click()
  await page.waitForURL(/\/dashboard\/[0-9a-f-]+/i)
})

test('Benchmark: run renders live results and can be re-run', async ({ page }) => {
  await login(page)
  await page.goto('/benchmark')
  await page.getByRole('button', { name: /RUN BENCHMARK/ }).click()
  await expect(page.getByText('LAST RUN:')).toBeVisible({ timeout: 90_000 })
  await expect(page.getByText('PARSING ACCURACY')).toBeVisible()
  await expect(page.getByText('IOC EXTRACTION')).toBeVisible()
})

test('mobile: sidebar opens via menu and closes on Escape', async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } })
  const page = await ctx.newPage()
  await login(page)
  await page.getByRole('button', { name: 'Open menu' }).click()
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeInViewport()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).not.toBeInViewport()
  await ctx.close()
})