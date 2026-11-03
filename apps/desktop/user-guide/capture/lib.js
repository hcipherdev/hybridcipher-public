// Shared helpers for the guide capture scripts.
const path = require('path');

const APP = path.resolve(__dirname, '../../src/index.html');

// Opens the real desktop UI with the mock backend. `scripts` are extra mock files
// loaded before mock-tauri.js (e.g. mock-team.js); `storage` seeds localStorage.
async function openApp(browser, { state = {}, scripts = [], storage = {} } = {}) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2 });
    page.on('pageerror', (e) => console.log('pageerror:', e.message.slice(0, 160)));
    await page.addInitScript(({ state, storage }) => {
        window.__GUIDE_STATE__ = state;
        try {
            localStorage.setItem('hybridcipher_legal_acceptance_v1',
                JSON.stringify({ version: '2026-09', acceptedAt: '2026-10-01T00:00:00Z' }));
            for (const [key, value] of Object.entries(storage)) localStorage.setItem(key, value);
        } catch (_) { /* storage unavailable */ }
    }, { state, storage });
    for (const script of scripts) await page.addInitScript({ path: path.resolve(__dirname, script) });
    await page.addInitScript({ path: path.resolve(__dirname, 'mock-tauri.js') });
    await page.goto('file://' + APP);
    await page.waitForTimeout(1200);
    return page;
}

async function hideToasts(page) {
    await page.evaluate(() => document.querySelectorAll('.notification, .toast, #notificationContainer > *')
        .forEach((el) => el.remove()));
}

// Draws a guide highlight ring around the element the step talks about.
async function highlight(page, selector) {
    await page.evaluate((selector) => {
        document.querySelectorAll('.guide-highlight').forEach((el) => el.remove());
        const target = document.querySelector(selector);
        if (!target) return;
        const r = target.getBoundingClientRect();
        const ring = document.createElement('div');
        ring.className = 'guide-highlight';
        Object.assign(ring.style, {
            position: 'fixed', left: `${r.left - 6}px`, top: `${r.top - 6}px`,
            width: `${r.width + 12}px`, height: `${r.height + 12}px`,
            border: '3px solid #f5b83d', borderRadius: '12px', zIndex: 2147483647,
            boxShadow: '0 0 0 4px rgba(245,184,61,0.25)', pointerEvents: 'none',
        });
        document.body.appendChild(ring);
    }, selector);
}

async function clearHighlight(page) {
    await page.evaluate(() => document.querySelectorAll('.guide-highlight').forEach((el) => el.remove()));
}

// Saves one guide frame. Toasts are removed so each frame is clean.
async function shot(page, dir, name, selector = null) {
    await page.waitForTimeout(500);
    await hideToasts(page);
    if (selector) await highlight(page, selector);
    await page.screenshot({ path: path.join(dir, `${name}.jpg`), type: 'jpeg', quality: 85 });
    await clearHighlight(page);
    console.log('saved', name);
}

module.exports = { openApp, hideToasts, highlight, clearHighlight, shot };
