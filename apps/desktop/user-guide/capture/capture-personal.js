// Clicks through the personal (this-device) flow in the real desktop UI, backed by
// mock-tauri.js, and saves one screenshot per guide step into ../site/img/personal/.
// Run: node capture-personal.js
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const { openApp, shot } = require('./lib');

const OUT = path.resolve(__dirname, '../site/img/personal');

(async () => {
    fs.mkdirSync(OUT, { recursive: true });
    const browser = await chromium.launch();
    const page = await openApp(browser, {
        state: { localVault: { fresh_device: true }, pickFolder: '/Users/alex/Documents/Personal' },
    });

    // 1. First launch opens straight into a vault on this device.
    await shot(page, OUT, '01-welcome', '#firstRunGetStartedBtn');

    // 2. Home with the Get started checklist.
    await page.click('#firstRunGetStartedBtn');
    await shot(page, OUT, '02-home', '#gettingStartedPanel');

    // 3. Recovery kit: intro, then the recovery key.
    await page.click('#gettingStartedList button:has-text("Save recovery kit")');
    await shot(page, OUT, '03-kit-intro', '#saveLocalRecoveryKitBtn');
    await page.click('#saveLocalRecoveryKitBtn');
    await page.fill('#localRecoveryKitCheckInput', 'R8NV');
    await shot(page, OUT, '04-kit-key', '#localRecoveryKitConfirm .recovery-code-box');
    await page.click('#confirmLocalRecoveryKitBtn');

    // 4. Protect a folder (the folder picker is mocked to return a demo path).
    await page.click('#gettingStartedList button:has-text("Choose a folder")');
    await page.waitForSelector('#actionPromptModal[style*="flex"]');
    await shot(page, OUT, '05-add-folder', '#actionPromptPrimaryBtn');
    await page.click('#actionPromptPrimaryBtn');
    await page.waitForTimeout(1000);
    await shot(page, OUT, '06-folder-protected', '#gettingStartedList li:nth-child(3)');

    // 5. Mount it to work with the files in Finder.
    await page.click('#gettingStartedList button:has-text("Mount folder")');
    await page.waitForTimeout(3000);
    await shot(page, OUT, '07-mounted', '.folder-detail-actions .btn-primary');

    // 6. Optional: create an account to use the files on other devices.
    await page.click('#sidebarHomeBtn');
    await page.waitForTimeout(600);
    await page.click('#gettingStartedOptionalBtn');
    await page.waitForTimeout(600);
    await shot(page, OUT, '08-other-devices', '#localUpgradeModal .modal-content');

    await browser.close();
})();
