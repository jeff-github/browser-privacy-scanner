const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const TARGET_URL = process.env.TARGET_URL || 'http://localhost:3000';
const LOGIN_EMAIL = process.env.LOGIN_EMAIL || '';
const LOGIN_PASSWORD = process.env.LOGIN_PASSWORD || '';
const FAIL_ON_FINDINGS = (process.env.PHI_FAIL_ON_FINDINGS || 'true').toLowerCase() !== 'false';

const scannerScript = fs.readFileSync(path.join(__dirname, 'browser_phi_scanner_v2.js'), 'utf8');

test('browser PHI scan', async ({ page }) => {
  await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded' });

  // Optional generic login flow. Customize selectors to your portal.
  if (LOGIN_EMAIL && LOGIN_PASSWORD) {
    const emailSelectors = ['input[type="email"]', 'input[name="email"]', '#email'];
    const passwordSelectors = ['input[type="password"]', 'input[name="password"]', '#password'];
    const submitSelectors = ['button[type="submit"]', 'input[type="submit"]'];

    let emailFilled = false;
    for (const sel of emailSelectors) {
      const el = page.locator(sel).first();
      if (await el.count()) {
        await el.fill(LOGIN_EMAIL);
        emailFilled = true;
        break;
      }
    }

    let passwordFilled = false;
    for (const sel of passwordSelectors) {
      const el = page.locator(sel).first();
      if (await el.count()) {
        await el.fill(LOGIN_PASSWORD);
        passwordFilled = true;
        break;
      }
    }

    if (emailFilled && passwordFilled) {
      for (const sel of submitSelectors) {
        const btn = page.locator(sel).first();
        if (await btn.count()) {
          await btn.click();
          break;
        }
      }
      await page.waitForLoadState('networkidle').catch(() => {});
    }
  }

  // Inject scanner
  await page.addInitScript(scannerScript);
  await page.evaluate(scannerScript);

  // Give app time to render and network hooks time to observe activity.
  await page.waitForTimeout(3000);

  // Optional lightweight navigation stimulus. Customize as needed.
  const links = page.locator('a');
  const linkCount = await links.count();
  for (let i = 0; i < Math.min(linkCount, 3); i++) {
    const href = await links.nth(i).getAttribute('href').catch(() => null);
    if (href && !href.startsWith('javascript:') && !href.startsWith('#')) {
      await links.nth(i).click().catch(() => {});
      await page.waitForLoadState('networkidle').catch(() => {});
      await page.waitForTimeout(1000);
      break;
    }
  }

  const results = await page.evaluate(() => window.__PHI_SCAN_RESULTS__ || null);

  const outPath = path.join(process.cwd(), 'playwright-phi-results.json');
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2), 'utf8');
  test.info().attach('playwright-phi-results', {
    body: JSON.stringify(results, null, 2),
    contentType: 'application/json',
  });

  console.log('PHI scan results written to', outPath);
  console.log(JSON.stringify(results, null, 2));

  expect(results).not.toBeNull();

  const findings = (results && results.findings) || [];
  if (FAIL_ON_FINDINGS) {
    expect(findings, `Potential PHI findings detected. See ${outPath}`).toHaveLength(0);
  }
});
