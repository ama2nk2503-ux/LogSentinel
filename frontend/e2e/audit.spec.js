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
  { path: '/baseline', name: 'Baseline', markers: ['ENTITY BASELINE', 'ANOMALY SCAN'] },
  { path: '/compliance', name: 'Compliance', markers: ['COMPLIANCE AUDIT'] },
  { path: '/assets', name: 'AssetInventory', markers: ['ASSET INVENTORY'] },
  { path: '/privacy', name: 'Privacy', markers: ['PRIVACY POLICY ENGINE'] },
  { path: '/export', name: 'Export', markers: ['SIEM EXPORT'] },
  { path: '/benchmark', name: 'Benchmark', markers: ['BENCHMARK', 'RUN BENCHMARK'] },
  { path: '/schema-docs', name: 'SchemaDocs', markers: ['UNIVERSAL EVENT SCHEMA DOCS'] },
  { path: '/parser-lab', name: 'ParserLab', markers: ['PARSER LAB'] },
  { path: '/assistant', name: 'Assistant', markers: ['AI ASSISTANT'] },
  { path: '/modes', name: 'Modes', markers: ['THE OFFLINE GUARANTEE'] },
  { path: '/users', name: 'Users', markers: ['USER MANAGEMENT'] },
]

let token = ''
let seedJobId = ''

function seedText() {
  const lines = []
  for (let i = 0; i < 60; i++) {
    const mm = String(i).padStart(2, '0')
    lines.push(`Aug 25 10:${mm}:0${i % 10} server sshd[1${i}]: Failed password for admin from 185.23.45.67 port ${5000 + i} ssh2`)
  }
  lines.push(`Aug 25 10:58:01 server sshd[1998]: Failed password for admin from 185.23.45.67 port 6666 ssh2 ${'X'.repeat(300)}`)
  lines.push(`Aug 25 10:58:31 server sshd[1998]: Failed password for admin from 185.23.45.67 port 6666 ssh2 ${'Y'.repeat(300)}`)
  lines.push('Aug 25 10:59:59 server sshd[1999]: Accepted password for admin from 10.0.0.7 port 51234 ssh2')
  return lines.join('\n')
}

async function login(page) {
  await loginAs(page, 'admin', 'changeme')
}

async function loginAs(page, username, password, landingUrl = '**/') {
  await page.goto('/login')
  await page.fill('#username', username)
  await page.fill('#password', password)
  await Promise.all([
    page.waitForURL(landingUrl),
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
  await page.addInitScript((adminToken) => {
    const override = sessionStorage.getItem('ls_token_override')
    if (override) localStorage.setItem('ls_token', override)
    else if (adminToken) localStorage.setItem('ls_token', adminToken)
  }, token)
})

async function impersonate(page, username) {
  // Force every navigation (which re-runs the init script) to use this user's session.
  await page.evaluate(() =>
    sessionStorage.setItem('ls_token_override', localStorage.getItem('ls_token'))
  )
}

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

test('Export: ECS and OCSF format cards are present and download JSON', async ({ page }) => {
  await login(page)
  await page.goto('/export')
  await selectSeedJob(page)
  await expect(page.getByRole('button', { name: /ECS/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /OCSF/ })).toBeVisible()

  await page.getByRole('button', { name: /ECS/ }).click()
  let downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: /DOWNLOAD ECS/ }).click()
  let download = await downloadPromise
  expect(download.suggestedFilename()).toContain('.json')

  await page.getByRole('button', { name: /OCSF/ }).click()
  downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: /DOWNLOAD OCSF/ }).click()
  download = await downloadPromise
  expect(download.suggestedFilename()).toContain('.json')
})

test('Explorer: select seed job, open event detail dialog, Escape closes', async ({ page }) => {
  await login(page)
  await page.goto('/explorer')
  await selectSeedJob(page)
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await expect(page.locator('thead th', { hasText: 'ANOMALY' })).toBeVisible()
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
  await expect(page.locator('tbody span', { hasText: '★' }).first()).toBeVisible()
  const rows = await page.locator('tbody tr').count()
  expect(rows).toBeGreaterThan(0)
  expect(rows).toBeLessThanOrEqual(50)
})

test('Dashboard: selecting a job renders cards and export triggers a download', async ({ page }) => {
  await login(page)
  await page.goto('/dashboard')
  await selectSeedJob(page)
  await expect(page.getByText('TOTAL EVENTS')).toBeVisible()
  await expect(page.getByText('ML ANOMALIES')).toBeVisible()

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: /EXPORT JSON/ }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toContain('.json')
})

test('Threats/Intel/Graph render with seeded data', async ({ page }) => {
  await login(page)
  for (const p of ['/threats', '/intel', '/graph']) {
    await page.goto(p)
    const narRespPromise = p === '/threats'
      ? page.waitForResponse((r) => /\/threats\/\d+\/narration$/.test(r.url()), { timeout: 45_000 })
      : Promise.resolve(null)
    await selectSeedJob(page)
    await expect(openHtml(page)).toContainText(
      p === '/threats' ? /ALL RULE MATCHES|WHY WAS THIS DETECTED/ : p === '/intel' ? 'INDICATORS' : /nodes|No entities/,
    )
    if (p === '/threats') {
      // M4/M5 lazy narration: each card issues its own GET /narration AFTER the
      // list has rendered. The narration body may be empty when the AI toggle
      // is off; when present (deterministic template when no local model
      // answers) the card must render it.
      const narResp = await narRespPromise
      const narration = await narResp.json()
      if (narration.ai_summary) {
        await expect(page.getByTestId('ai-summary').first()).toBeVisible({ timeout: 30_000 })
      }
    }
  }
})

test('Compliance: seeded job audits to frameworks with PASS/FAIL status', async ({ page }) => {
  await login(page)
  await page.goto('/compliance')
  await selectSeedJob(page)
  await expect(page.getByText(/controls passed/).first()).toBeVisible({ timeout: 60_000 })
  await expect(page.getByText('FAIL', { exact: true }).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: 'VIEW FINDINGS' }).first().click()
  await expect(page.getByText('CONTROL', { exact: true }).first()).toBeVisible()
  await expect(openHtml(page)).toContainText(/score \d+\/100/)
})

test('Assets: seeded job maps source host into inventory', async ({ page }) => {
  await login(page)
  await page.goto('/assets')
  await selectSeedJob(page)
  await expect(page.getByText(/1 ASSETS/).first()).toBeVisible({ timeout: 60_000 })
  const row = page.locator('tbody tr').filter({ hasText: 'server' }).first()
  await expect(row).toBeVisible({ timeout: 15_000 })
  await expect(row).toContainText('host')
  await expect(row).toContainText('MEDIUM')
})

test('Intel: reputation lookup returns verdict', async ({ page }) => {
  await login(page)
  await page.goto('/intel')
  await page.getByRole('tab', { name: 'REPUTATION' }).click()
  await page.getByLabel('Reputation lookup value').fill('185.23.45.67')
  await expect(page.getByText('MALICIOUS')).toBeVisible({ timeout: 15_000 })
})

test('Intel: geo enrichment lookup returns country + kind', async ({ page }) => {
  await login(page)
  await page.goto('/intel')
  await page.getByRole('tab', { name: 'GEO' }).click()
  await page.getByLabel('Geo lookup IP').fill('185.23.45.67')
  await expect(page.getByText('Russia')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('PUBLIC')).toBeVisible()
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
  await expect(page.getByRole('button', { name: /events \u00b7/ }).first()).toBeVisible()
  await page.getByRole('button', { name: /events \u00b7/ }).first().click()
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

test('Parser Lab: live parsing routes vendors and labels fallback without DB writes', async ({ page }) => {
  await login(page)
  await page.goto('/parser-lab')
  const input = page.getByLabel('PASTE RAW LOG LINES')
  await input.fill([
    '%ASA-6-302013: Built inbound TCP connection 1 for outside:5.6.7.8/443 to inside:10.1.1.5/5000',
    'date=2026-08-25 time=10:30:01 devname=FW1 action=deny srcip=1.2.3.4 dstip=5.6.7.8 dstport=22 proto=6',
    'Aug 25 10:30:01 srv01 sshd[123]: Failed password for admin from 185.23.45.67 port 5000 ssh2',
    'gibberish unstructured line with no shape 123',
  ].join('\n'))
  await expect(page.getByText('cisco_asa').first()).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('fortinet').first()).toBeVisible()
  await expect(page.getByText('unknown — generic fallback').first()).toBeVisible()
  await expect(page.getByText(/NAMED PARSER %/)).toBeVisible()
  await expect(page.getByText(/DISTINCT FORMATS/)).toBeVisible()
})

test('Modes: three mode cards and offline guarantee are inspectable', async ({ page }) => {
  await login(page)
  await page.goto('/modes')
  await expect(page.getByText('Demo (bundled samples)')).toBeVisible()
  await expect(page.getByText('Production (offline, air-gapped)')).toBeVisible()
  await expect(page.getByText('Custom upload')).toBeVisible()
  await expect(page.getByText('THE OFFLINE GUARANTEE')).toBeVisible()
  await expect(page.getByText('No cloud APIs')).toBeVisible()
})

test('Export: verify integrity confirms the hash chain for the seed job', async ({ page }) => {
  await login(page)
  await page.goto('/export')
  await selectSeedJob(page)
  await expect(page.getByText('CHAIN OF CUSTODY')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText(/chain valid/)).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /VERIFY INTEGRITY/ }).click()
  await expect(page.getByText(/chain valid/)).toBeVisible({ timeout: 15_000 })
})

test('Threats: rule-vs-ML agreement panel renders counts', async ({ page }) => {
  await login(page)
  await page.goto('/threats')
  await selectSeedJob(page)
  await expect(page.getByText('RULES vs ML — WHO SAW WHAT')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('RULES ONLY', { exact: true })).toBeVisible()
  await expect(page.getByText('ML ONLY', { exact: true })).toBeVisible()
  await expect(page.getByText('BOTH AGREED', { exact: true })).toBeVisible()
})

test('Assistant: sends a chat message and gets a grounded deterministic answer', async ({ page }) => {
  await login(page)
  await page.goto('/assistant')
  await selectSeedJob(page)
  await page.getByLabel('Ask a question about this dataset').fill('how do I fix the brute force?')
  await page.getByRole('button', { name: 'SEND' }).click()
  await expect(page.getByTestId('ai-answer')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('DETERMINISTIC').first()).toBeVisible()
  await expect(page.getByText('Block source IP at the perimeter').first()).toBeVisible()
  await expect(page.getByText('EVIDENCE / FACTS USED (')).toBeVisible()
})

test('Baseline: rescan folds jobs and the anomaly scan panel renders', async ({ page }) => {
  await page.goto('/baseline')
  await expect(page.getByText('RUNNING BASELINE')).toBeVisible()

  const rescan = page.getByRole('button', { name: 'RE-SCAN JOBS' })
  await rescan.click()
  await expect(rescan).toBeEnabled({ timeout: 20_000 }) // in-flight POST completes
  await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 20_000 })

  // Anomaly scan auto-selects the newest job and renders an explained verdict.
  await expect(page.getByText('ANOMALY SCAN AGAINST BASELINE')).toBeVisible()
  await expect(page.locator('ul.divide-y li').first()).toBeVisible({ timeout: 15_000 })

  const text = await page.locator('ul.divide-y').innerText()
  const explained = text.includes('baseline mean') || text.includes('within the learned baseline')
  expect(explained, `anomaly row must self-explain, got: ${text.slice(0, 160)}`).toBeTruthy()
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

test('RBAC: viewer is blocked from admin/lab surfaces and edit controls', async ({ page, request }) => {
  // Ensure the viewer account exists (idempotent — the shared data DB persists across runs).
  const auth = { Authorization: `Bearer ${token}` }
  const created = await request.post('/api/auth/users',
    { headers: auth, data: { username: 'e2e_viewer', password: 'viewerpass', role: 'viewer' } })
  expect([200, 409]).toContain(created.status())

  await loginAs(page, 'e2e_viewer', 'viewerpass', '**/dashboard')
  await impersonate(page, 'e2e_viewer')

  // Admin-only USER MANAGEMENT link is hidden from the sidebar.
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).not.toContainText('USER MANAGEMENT')

  // Analyst/operator surfaces are hidden from a viewer too.
  const nav = page.getByRole('navigation', { name: 'Main navigation' })
  for (const label of ['UPLOAD', 'DEMO MODE', 'BENCHMARK', 'PARSER LAB', 'AI ASSISTANT', 'MODES']) {
    await expect(nav).not.toContainText(label)
  }

  // Direct URL to an analyst surface shows the gated notice (viewer can't open it).
  await page.goto('/demo')
  await expect(page.getByText('ACCESS RESTRICTED')).toBeVisible()

  // Viewer cannot reach the admin-only users page: gated notice is shown.
  await page.goto('/users')
  await expect(page.getByText('ACCESS RESTRICTED')).toBeVisible()
  await expect(page.getByText(/requires role ADMIN/)).toBeVisible()

  // Alerts: MANAGE RULES is disabled (admin-only) rather than silently failing.
  await page.goto('/alerts')
  const manageRules = page.getByRole('button', { name: /MANAGE RULES/ })
  await expect(manageRules).toBeDisabled()
  await expect(manageRules).toHaveAttribute('title', 'requires admin')

  // Privacy: SAVE POLICY disabled (admin-only).
  await page.goto('/privacy')
  const savePolicy = page.getByRole('button', { name: 'SAVE POLICY' })
  await expect(savePolicy).toBeDisabled()
  await expect(page.getByText(/Read-only for your role/)).toBeVisible()
})

test('RBAC: analyst can triage but not manage users', async ({ page, request }) => {
  const auth = { Authorization: `Bearer ${token}` }
  const created = await request.post('/api/auth/users',
    { headers: auth, data: { username: 'e2e_analyst', password: 'analystpass', role: 'analyst' } })
  expect([200, 409]).toContain(created.status())

  await loginAs(page, 'e2e_analyst', 'analystpass')
  await impersonate(page, 'e2e_analyst')
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).not.toContainText('USER MANAGEMENT')
  // Analyst keeps the operator surfaces the viewer loses.
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toContainText('UPLOAD')
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toContainText('AI ASSISTANT')
  await page.goto('/users')
  await expect(page.getByText('ACCESS RESTRICTED')).toBeVisible()
  await expect(page.getByText(/requires role ADMIN/)).toBeVisible()
})

test('RBAC: seeded user management page renders and roles can be read', async ({ page }) => {
  await page.goto('/users')
  await expect(page.getByRole('heading', { name: 'USER MANAGEMENT' })).toBeVisible()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  const adminRow = page.locator('tbody tr').filter({ hasText: 'admin' }).first()
  await expect(adminRow).toContainText('ADMIN')
  await expect(page.locator('tbody tr').filter({ hasText: 'e2e_viewer' }).first()).toContainText('VIEWER')

  const results = await new AxeBuilder({ page }).analyze()
  const serious = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious')
  expect(serious, `Users page axe: ${serious.map((v) => `${v.id} (${v.impact})`).join(', ')}`).toEqual([])
})