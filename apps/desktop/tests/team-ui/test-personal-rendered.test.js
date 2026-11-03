// Tests actual desktop HTML/CSS visibility, Personal baseline navigation, operation retries, a long failed operation fitting on screen, and secure input in Chromium
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const sourceRoot = fileURLToPath(new URL('../../src/', import.meta.url));
const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));
const baseline = '3cfff8043e19e90c9dbc9f0324c6e806d6cfa2ed';
let playwright;
try {
    playwright = await import(process.env.HYBRIDCIPHER_PLAYWRIGHT_MODULE
        ? pathToFileURL(process.env.HYBRIDCIPHER_PLAYWRIGHT_MODULE).href : 'playwright');
} catch (error) {
    if (process.env.HYBRIDCIPHER_PLAYWRIGHT_MODULE) throw error;
}

function source(name, historical = false) {
    return historical ? execFileSync('git', ['show', `${baseline}:apps/desktop/src/${name}`], { cwd: repoRoot, encoding: 'utf8' })
        : fs.readFileSync(path.join(sourceRoot, name), 'utf8');
}

test('desktop rendered regressions', { skip: !playwright && 'Provide Playwright through HYBRIDCIPHER_PLAYWRIGHT_MODULE to run rendered checks.' }, async t => {
    let browser;
    try {
        browser = await playwright.chromium.launch({ headless: true,
            ...(process.env.HYBRIDCIPHER_BROWSER_EXECUTABLE ? { executablePath: process.env.HYBRIDCIPHER_BROWSER_EXECUTABLE } : { channel: 'chrome' }) });
        async function pageFor(historical = false) {
            const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
            await page.route('**/*', async route => {
                const name = path.basename(new URL(route.request().url()).pathname);
                if (['logo.png', 'logo.svg'].includes(name)) {
                    await route.fulfill({ contentType: name.endsWith('.png') ? 'image/png' : 'image/svg+xml', body: fs.readFileSync(path.join(sourceRoot, name)) });
                } else await route.fulfill({ contentType: 'text/html', body: '<!doctype html><html><body></body></html>' });
            });
            await page.goto('http://desktop.test/');
            await page.setContent(source('index.html', historical).replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<link\b[^>]*>/gi, ''));
            await page.addStyleTag({ content: source('styles.css', historical) });
            for (const name of ['security-utils.js', 'ui-utils.js', 'beta-ux-utils.js']) {
                await page.addScriptTag({ content: source(name, historical) });
            }
            if (!historical) await page.addScriptTag({ content: source('app-team-methods.js') });
            await page.addScriptTag({ content: source('app.js', historical).split('// Initialize app')[0] + '\nwindow.TestAppClass = HybridCipherApp;' });
            await page.evaluate(() => {
                window.testApp = Object.assign(Object.create(window.TestAppClass.prototype), {
                    currentUser: 'personal@example.com', currentDeviceId: 'primary', isLoggedIn: true,
                    activeWorkspaceType: 'personal', activeWorkspaceView: 'home', appMode: 'individual',
                    workspaceGroupContext: { group_id: 'personal-group', organization_id: null, role: 'owner', readiness: 'ready' },
                    workspaceContextReady: true, workspaceSwitchSequence: 1, desktopAccountGeneration: 1,
                    teamLicenseStatus: { workspace: 'personal', online: true, can_write: true },
                    enrolledFolders: [], folderSearchQuery: '', activeMountsByRootId: {}, activeMountDetailsByRootId: {},
                    isRootMounted() { return false; },
                    homeStatusSnapshot: { mfa_enabled: true, current_device: { device_id: 'primary', is_verified: true },
                        scan_status_available: true, device_counts: {}, folder_attention: {}, unavailable_sections: [] },
                });
                document.getElementById('welcomeScreen').style.display = 'none';
                document.getElementById('appContainer').style.display = 'flex';
                window.testApp.applyAppMode();
                window.testApp.setWorkspaceView('home');
                window.testApp.updateWorkspaceHomeSummary();
                window.testApp.renderTeamLicenseSettings?.();
            });
            return page;
        }

        async function personalEnrollmentPage(readiness = 'uninitialized') {
            const page = await pageFor();
            await page.evaluate(async initialReadiness => {
                window.enrollmentFixture = { readiness: initialReadiness, requests: [], pickerCalls: [] };
                const invoke = async (command, args = {}) => {
                    enrollmentFixture.requests.push({ command, args });
                    if (command === 'get_team_license_status') throw new Error('Team licensing unavailable');
                    if (command === 'get_workspace_group_context') return {
                        group_id: 'personal-group', name: 'Personal', organization_id: null, role: 'owner',
                        readiness: enrollmentFixture.readiness,
                        groups: [{ id: 'personal-group', organization_id: null, current_epoch_id: 'personal-epoch' }],
                    };
                    if (command === 'list_enrolled_folders' || command === 'list_active_mounts') return { success: true, data: [] };
                    if (command === 'get_individual_home_status') return { success: true, data: {
                        mfa_enabled: true, current_device: { device_id: 'primary', is_verified: false },
                        scan_status_available: true, device_counts: {}, folder_attention: {}, unavailable_sections: [],
                    } };
                    if (command === 'get_personal_devices_overview') return { success: true, data: {
                        current_device: { device_id: 'primary', status: 'pending', is_current_device: true, is_verified: false },
                        trusted_devices: [], setup_devices: [], review_devices: [],
                        device_trust: { device_id: 'primary', approved: false, identity_key_sha256: '1'.repeat(64) },
                    } };
                    throw new Error(`Unexpected fixture IPC: ${command}`);
                };
                window.HybridCipherTauri = { invoke };
                window.__TAURI__ = { dialog: { open: async options => { enrollmentFixture.pickerCalls.push(options); return null; } } };
                testApp.workspaceGroupContext = null;
                testApp.workspaceContextReady = false;
                testApp.teamLicenseStatus = null;
                testApp.workspaceChoiceLoaded = true;
                testApp.userFolderPreferences = {};
                testApp.unmountingRootIds = new Set();
                testApp.setupEventListeners();
                testApp.applyAppMode();
                await testApp.refreshTeamLicenseStatus({ silent: true });
                await testApp.ensurePersonalWorkspaceReady();
            }, readiness);
            return page;
        }

        await t.test('Personal hides Team setup, roles, administration, and Activity in the rendered page', async () => {
            const page = await pageFor();
            for (const id of ['teamSetupNotice', 'teamSetupRetryBtn', 'teamSetupCompleteBtn', 'teamSetupCheckStatusBtn', 'workspaceContextLabel', 'desktopOperationsBtn', 'sidebarTeamNav', 'workspaceSelector', 'workspaceLicenseBadge']) {
                assert.equal(await page.locator(`#${id}`).isVisible(), false, id);
            }
            const snapshot = await page.locator('#appContainer').ariaSnapshot();
            assert.ok(!snapshot.includes('Retry setup') && !snapshot.includes('Team administration') && !snapshot.includes('Activity'));
            await page.evaluate(() => {
                testApp.desktopOperation = { id: 'verify', status: 'succeeded', output: [], phase: 'Complete' };
                testApp.desktopOperationRequest = { kind: 'cli' };
                testApp.desktopOperationContext = { account: testApp.currentUser, generation: testApp.desktopAccountGeneration,
                    sequence: testApp.workspaceSwitchSequence, workspace: 'personal', groupId: 'personal-group' };
                testApp.renderDesktopOperation();
                testApp.openDesktopOperation();
            });
            assert.equal(await page.locator('#desktopOperationModal').isVisible(), true);
            assert.equal(await page.locator('#desktopOperationRetryBtn').isVisible(), false);
            assert.equal(await page.locator('#desktopOperationsBtn').isVisible(), false);
            assert.ok(!(await page.locator('#desktopOperationModal').ariaSnapshot()).includes('Retry'));
            await page.close();
        });

        await t.test('a long failed operation keeps its close button on screen', async () => {
            const page = await pageFor();
            await page.setViewportSize({ width: 1280, height: 720 });
            await page.evaluate(() => {
                const output = Array.from({ length: 120 }, (_, index) => `ℹ CLI transcript line ${index}`);
                output.push('✗ Error: Migration error: The server rejected the key rotation (400 Bad Request): Key version 3 was already used');
                // An older app put the whole transcript in the error; any long message must still fit.
                testApp.desktopOperation = { id: 'rekey', status: 'failed', output, phase: 'Action needs attention',
                    error: { code: 'action_failed', message: output.join('\n') } };
                testApp.desktopOperationRequest = { kind: 'cli' };
                testApp.desktopOperationContext = { account: testApp.currentUser, generation: testApp.desktopAccountGeneration,
                    sequence: testApp.workspaceSwitchSequence, workspace: 'personal', groupId: 'personal-group' };
                testApp.renderDesktopOperation();
                testApp.openDesktopOperation();
                document.getElementById('desktopOperationDetails').open = true;
            });
            for (const id of ['closeDesktopOperationBtn', 'desktopOperationTitle']) {
                const box = await page.locator(`#${id}`).boundingBox();
                assert.ok(box && box.y >= 0 && box.y + box.height <= 720, `${id} is on screen: ${JSON.stringify(box)}`);
            }
            const content = await page.locator('#desktopOperationModal .modal-content').boundingBox();
            assert.ok(content.height <= 720, `window fits: ${content.height}`);
            // The Close button at the bottom is reachable by scrolling the window body.
            await page.locator('#desktopOperationCloseBtn').scrollIntoViewIfNeeded();
            const close = await page.locator('#desktopOperationCloseBtn').boundingBox();
            assert.ok(close.y >= 0 && close.y + close.height <= 720);
            await page.close();
        });

        await t.test('Team entitlement shows only the workspace selector while Personal is selected', async () => {
            const page = await pageFor();
            await page.evaluate(() => {
                testApp.teamLicenseStatus = { workspace: 'team', organization: { id: 'organization', role: 'owner' }, online: true, can_write: true };
                testApp.applyAppMode(); testApp.renderTeamLicenseSettings();
                document.getElementById('settingsModal').style.display = 'flex';
            });
            for (const id of ['teamSetupNotice', 'workspaceContextLabel', 'desktopOperationsBtn', 'sidebarTeamNav', 'workspaceLicenseBadge', 'settingsTeamSection', 'settingsOpenTeamBtn']) {
                assert.equal(await page.locator(`#${id}`).isVisible(), false, id);
            }
            assert.equal(await page.locator('#workspaceSelector').isVisible(), true);
            assert.equal(await page.locator('#workspaceSelector').inputValue(), 'personal');
            await page.close();
        });

        await t.test('Choosing Team in the selector opens it through Team setup and reverts when it fails', async () => {
            const page = await pageFor();
            const result = await page.evaluate(async () => {
                const calls = [];
                window.HybridCipherTauri = { invoke: async command => { calls.push(`ipc-${command}`); return null; } };
                testApp.teamLicenseStatus = { workspace: 'team', organization: { id: 'organization', role: 'owner' }, online: true, can_write: true };
                testApp.openEntitledTeamWorkspace = async () => { calls.push('open-team'); return false; };
                testApp.selectWorkspaceType = async type => { calls.push(`select-${type}`); return false; };
                testApp.setupEventListeners();
                testApp.applyAppMode();
                const selector = document.getElementById('workspaceSelector');
                selector.value = 'team';
                selector.dispatchEvent(new Event('change'));
                await new Promise(resolve => setTimeout(resolve, 0));
                return { calls, value: selector.value };
            });
            assert.deepEqual(result.calls, ['open-team']);
            assert.equal(result.value, 'personal');
            await page.close();
        });

        await t.test('Personal Add protected folder rechecks local readiness and opens the picker when Team licensing fails', async () => {
            const page = await personalEnrollmentPage();
            assert.equal(await page.evaluate(() => testApp.workspaceContextReady), false);
            assert.equal(await page.locator('#homeAddFolderBtn').isEnabled(), true);
            assert.equal(await page.locator('#addFolderBtn').isEnabled(), true);
            const readsBeforeClick = await page.evaluate(() => enrollmentFixture.requests.filter(request => request.command === 'get_workspace_group_context').length);
            await page.evaluate(() => { enrollmentFixture.readiness = 'ready'; });
            await page.locator('#homeAddFolderBtn').click();
            await page.waitForFunction(() => enrollmentFixture.pickerCalls.length === 1);
            const state = await page.evaluate(() => ({
                requests: enrollmentFixture.requests, pickerCalls: enrollmentFixture.pickerCalls,
                ready: testApp.workspaceContextReady, workspace: testApp.activeWorkspaceType, mode: testApp.appMode,
            }));
            assert.ok(state.requests.some(request => request.command === 'get_team_license_status'));
            assert.ok(state.requests.filter(request => request.command === 'get_workspace_group_context').length > readsBeforeClick);
            assert.ok(state.requests.filter(request => request.command === 'get_workspace_group_context').every(request => request.args.workspace === 'personal'));
            assert.equal(state.ready, true);
            assert.equal(state.workspace, 'personal');
            assert.equal(state.mode, 'individual');
            assert.deepEqual(state.pickerCalls[0], { directory: true, multiple: false, title: 'Select folder to enroll' });
            assert.equal(await page.locator('#teamSetupNotice').isVisible(), false);
            await page.close();
        });

        await t.test('Personal missing keys remain blocked with a visible Personal explanation and no Team setup banner', async () => {
            const page = await personalEnrollmentPage('waiting_for_device_approval');
            assert.equal(await page.locator('#homeAddFolderBtn').isEnabled(), true);
            const readsBeforeClick = await page.evaluate(() => enrollmentFixture.requests.filter(request => request.command === 'get_workspace_group_context').length);
            await page.locator('#homeAddFolderBtn').click();
            const reason = page.locator('#notificationContainer .notification').filter({ hasText:
                'Your Personal encryption keys are not available on this device yet. Open Devices to complete device setup, then try again.' });
            await reason.waitFor({ state: 'visible' });
            const state = await page.evaluate(() => ({
                pickerCalls: enrollmentFixture.pickerCalls.length, ready: testApp.workspaceContextReady,
                reads: enrollmentFixture.requests.filter(request => request.command === 'get_workspace_group_context').length,
                workspace: testApp.activeWorkspaceType,
            }));
            assert.equal(state.pickerCalls, 0);
            assert.equal(state.ready, false);
            assert.ok(state.reads > readsBeforeClick);
            assert.equal(state.workspace, 'personal');
            assert.equal(await page.locator('#teamSetupNotice').isVisible(), false);
            assert.equal(await page.locator('#teamSetupRetryBtn').isVisible(), false);
            await page.close();
        });

        await t.test('Team retries are accessible only during recoverable failure and disappear after acknowledgement', async () => {
            const page = await pageFor();
            await page.evaluate(() => {
                testApp.activeWorkspaceType = 'team';
                testApp.teamLicenseStatus = { workspace: 'team', organization_id: 'organization', online: true, can_write: true };
                testApp.workspaceGroupContext = { group_id: 'team-group', organization_id: 'organization', role: 'owner', readiness: 'ready' };
                testApp.desktopOperationContext = { account: testApp.currentUser, generation: testApp.desktopAccountGeneration,
                    sequence: testApp.workspaceSwitchSequence, workspace: 'team', groupId: 'team-group' };
                testApp.desktopOperationRequest = { kind: 'switch_group', group_id: 'team-group' };
                testApp.desktopOperation = { id: 'switch', status: 'failed', output: [], error: { code: 'NETWORK_ERROR', message: 'Connection timed out' } };
                testApp.openDesktopOperation();
            });
            assert.equal(await page.locator('#desktopOperationModal').isVisible(), true);
            assert.equal(await page.locator('#desktopOperationRetryBtn').isVisible(), true);
            await page.locator('#desktopOperationRetryBtn').focus();
            assert.equal(await page.locator('#desktopOperationRetryBtn').evaluate(element => element === document.activeElement), true);
            assert.ok((await page.locator('#desktopOperationModal').ariaSnapshot()).includes('Retry'));
            await page.evaluate(() => {
                testApp.desktopOperation = { id: 'switch', status: 'succeeded', output: [], phase: 'Complete' };
                testApp.renderDesktopOperation();
            });
            assert.equal(await page.locator('#desktopOperationRetryBtn').isVisible(), false);
            assert.ok(!(await page.locator('#desktopOperationModal').ariaSnapshot()).includes('Retry'));
            assert.equal(await page.locator('#desktopOperationsBtn').isVisible(), true);
            await page.evaluate(() => testApp.closeDesktopOperation());
            assert.equal(await page.locator('#desktopOperationsBtn').isVisible(), false);
            await page.close();
        });

        await t.test('Personal header and sidebar match the pre-Team baseline', async () => {
            const old = await pageFor(true);
            const current = await pageFor();
            const visibleActions = page => page.locator('.header-right, .sidebar-footer').evaluateAll(nodes => nodes.flatMap(node =>
                [...node.querySelectorAll('button, select')].filter(element => element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden')
                    .map(element => (element.textContent || '').replace(/\s+/g, ' ').trim())));
            assert.deepEqual(await visibleActions(current), await visibleActions(old));
            const output = process.env.HYBRIDCIPHER_UI_SCREENSHOT_DIR;
            if (output) {
                fs.mkdirSync(output, { recursive: true });
                await old.screenshot({ path: path.join(output, 'personal-baseline.png'), fullPage: true });
                await current.screenshot({ path: path.join(output, 'personal-current.png'), fullPage: true });
            }
            await old.close(); await current.close();
        });

        // Opens the account panel with fixed security warnings, fingerprint and trust responses.
        async function accountPanelPage({ mfaEnabled }) {
            const page = await pageFor();
            await page.evaluate(async enabled => {
                window.panelFixture = { copied: [], requests: [] };
                window.HybridCipherTauri = { invoke: async command => {
                    panelFixture.requests.push(command);
                    if (command === 'get_security_status') return { success: true, data: { mfa_enabled: enabled, recovery_auto_backup_ok: true } };
                    if (command === 'get_current_device_fingerprint') return { success: true, data: { device_id: 'primary', fingerprint: 'a1b2c3d4e5f60718' } };
                    if (command === 'get_device_trust_status') return { success: true, data: { approved: true, fingerprint_verified: false, can_revoke_other_devices: false } };
                    return { success: true, data: null };
                } };
                Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async value => panelFixture.copied.push(value) } });
                testApp.showNotification = () => {};
                testApp.securityStatus = { mfa_enabled: enabled, recovery_auto_backup_ok: true };
                testApp.updateSecurityBanner();
                testApp.setupEventListeners();
                document.getElementById('userStatusPill').click();
            }, mfaEnabled);
            await page.locator('#statusDeviceFingerprint').filter({ hasText: 'A1B2 C3D4 E5F6 0718' }).waitFor();
            await page.locator('#statusDeviceTrust').filter({ hasText: 'Not verified yet' }).waitFor();
            return page;
        }

        await t.test('the account panel opens without warnings and shows only this device fingerprint', async () => {
            const page = await accountPanelPage({ mfaEnabled: true });
            assert.equal(await page.locator('#statusWarningPanel').isVisible(), true);
            assert.equal(await page.locator('#statusWarningHeader').isVisible(), false);
            assert.equal(await page.locator('#statusWarningList').isVisible(), false);
            assert.equal(await page.locator('.status-warning-empty').count(), 0);
            assert.equal(await page.locator('#userStatusAlert').isVisible(), false, 'the fingerprint alone adds no alert');
            await page.locator('#statusCopyFingerprintBtn').click();
            assert.deepEqual(await page.evaluate(() => panelFixture.copied), ['A1B2 C3D4 E5F6 0718']);
            await page.close();
        });

        await t.test('the account panel keeps security warnings above the device fingerprint', async () => {
            const page = await accountPanelPage({ mfaEnabled: false });
            assert.equal(await page.locator('#statusWarningHeader').isVisible(), true);
            const warning = await page.locator('.status-warning-item').filter({ hasText: 'MFA not enabled' }).boundingBox();
            const device = await page.locator('#statusDeviceSection').boundingBox();
            assert.ok(warning && device && warning.y + warning.height <= device.y, 'warnings come before the fingerprint');
            await page.close();
        });

        await t.test('Personal Settings has only the explicit Team activation entry', async () => {
            const page = await pageFor();
            await page.evaluate(() => { document.getElementById('settingsModal').style.display = 'flex'; });
            assert.equal(await page.locator('#settingsTeamSection').isVisible(), false);
            assert.equal(await page.locator('#settingsOpenTeamBtn').isVisible(), true);
            await page.evaluate(() => testApp.openTeamActivationModal());
            assert.equal(await page.locator('#teamActivationModal').isVisible(), true);
            assert.equal(await page.locator('#teamActivationForm').isVisible(), true);
            assert.equal(await page.locator('#teamInvitationAcceptance').isVisible(), true);
            await page.close();
        });

        await t.test('legacy inline dialogs still open and password prompts clear their input', async () => {
            const page = await pageFor();
            for (const id of ['loginModal', 'settingsModal', 'desktopOperationModal']) {
                await page.evaluate(id => { document.getElementById(id).style.display = 'flex'; }, id);
                assert.equal(await page.locator(`#${id}`).isVisible(), true, id);
                await page.evaluate(id => { document.getElementById(id).style.display = 'none'; }, id);
            }
            await page.evaluate(() => {
                window.promptResult = testApp.promptForText('Confirm password', { inputType: 'password', preserveWhitespace: true });
            });
            assert.equal(await page.locator('#textPromptInput').getAttribute('type'), 'password');
            await page.locator('#textPromptInput').fill(' private value ');
            await page.locator('#submitTextPromptBtn').click();
            assert.equal(await page.evaluate(() => window.promptResult), ' private value ');
            assert.equal(await page.locator('#textPromptInput').inputValue(), '');
            assert.equal(await page.locator('#textPromptModal').isVisible(), false);
            await page.close();
        });
    } finally {
        await browser?.close();
    }
});
