const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadMethods(invoke, storage = new Map()) {
    const elements = new Map();
    const element = id => ({
        id,
        style: {},
        textContent: '',
        innerHTML: '',
        classList: {
            hidden: true,
            add(value) { if (value === 'hidden') this.hidden = true; },
            remove(value) { if (value === 'hidden') this.hidden = false; },
        },
        addEventListener(type, listener) { this[`on${type}`] = listener; },
        setAttribute(name, value) { this[name] = value; },
        remove() { elements.delete(this.id); },
    });
    for (const id of [
        'settingsUpdateStatus', 'settingsUpdatePreferenceRow', 'settingsUpdateActions',
        'settingsUpdateBadge', 'settingsOpenStoreUpdateBtn', 'storeUpdateOpenBtn', 'storeUpdateLaterBtn',
    ]) elements.set(id, element(id));
    const context = {
        window: {
            HybridCipherTauri: { invoke },
            localStorage: {
                getItem: key => storage.get(key) ?? null,
                setItem: (key, value) => storage.set(key, value),
            },
        },
        document: {
            getElementById: id => elements.get(id) || null,
            createElement: () => element(''),
            body: { appendChild: child => elements.set(child.id, child) },
        },
        console: { ...console, debug() {} },
    };
    vm.runInNewContext(
        fs.readFileSync(path.join(__dirname, '../src/app-update-methods.js'), 'utf8'),
        context,
    );
    return { methods: context.window.HybridCipherAppUpdateMethods, elements, storage };
}

test('Store update appears in the app and opens its Store page', async () => {
    const commands = [];
    const { methods, elements } = loadMethods(async name => {
        commands.push(name);
        if (name === 'get_app_version') return { success: true, data: '0.1.6' };
        if (name === 'check_for_updates') return { success: true, data: { available: true, source: 'microsoft_store' } };
        return { success: true, data: true };
    });
    const app = { ...methods, platformInfo: { update_channel: 'microsoft_store' }, updatePreference: 'manual' };
    await app.checkForUpdates();
    assert.equal(elements.get('settingsUpdateBadge').classList.hidden, false);
    assert.match(elements.get('settingsUpdateStatus').innerHTML, /Open Microsoft Store/);
    assert.ok(elements.get('updateBanner'));
    assert.equal(elements.get('settingsUpdatePreferenceRow').style.display, 'none');
    assert.equal(elements.get('settingsUpdateActions').style.display, '');

    await elements.get('storeUpdateOpenBtn').onclick();
    await elements.get('settingsOpenStoreUpdateBtn').onclick();
    assert.equal(commands.filter(name => name === 'open_store_update_page').length, 2);
    assert.equal(elements.has('updateBanner'), false);
});

test('Store checks reuse the persisted result but manual checking queries again', async () => {
    let checks = 0;
    const storage = new Map();
    const invoke = async name => {
        if (name === 'get_app_version') return { success: true, data: '0.1.6' };
        if (name === 'check_for_updates') {
            checks++;
            return { success: true, data: { available: checks === 1 } };
        }
    };
    const { methods, elements } = loadMethods(invoke, storage);
    const app = { ...methods, platformInfo: { update_channel: 'microsoft_store' } };
    await app.checkForUpdates();
    const restarted = loadMethods(invoke, storage);
    const restartedApp = { ...restarted.methods, platformInfo: { update_channel: 'microsoft_store' } };
    await restartedApp.checkForUpdates();
    assert.equal(checks, 1);
    await app.checkForUpdatesManual();
    assert.equal(checks, 2);
    assert.equal(app.availableUpdate, null);
    assert.equal(elements.get('settingsUpdateBadge').classList.hidden, true);
    assert.equal(elements.has('updateBanner'), false);
});

test('dismissing a Store banner does not hide the update badge', async () => {
    const { methods, elements } = loadMethods(async name => name === 'get_app_version'
        ? { success: true, data: '0.1.6' }
        : { success: true, data: { available: true } });
    const app = { ...methods, platformInfo: { update_channel: 'microsoft_store' } };
    await app.checkForUpdates();
    elements.get('storeUpdateLaterBtn').onclick();
    assert.equal(elements.has('updateBanner'), false);
    await app.checkForUpdatesManual();
    assert.equal(elements.has('updateBanner'), false);
    assert.equal(elements.get('settingsUpdateBadge').classList.hidden, false);
});

test('Store service failure is shown only for a manual check', async () => {
    const { methods, elements } = loadMethods(async name => name === 'get_app_version'
        ? { success: true, data: '0.1.6' }
        : { success: false, error: 'Store unavailable' });
    const app = { ...methods, platformInfo: { update_channel: 'microsoft_store' } };
    await app.checkForUpdatesManual();
    assert.match(elements.get('settingsUpdateStatus').textContent, /Store unavailable/);
    assert.equal(elements.get('settingsUpdateBadge').classList.hidden, true);
});

test('local channel still checks for updates', async () => {
    let command;
    const { methods } = loadMethods(async name => {
        command = name;
        return { success: true, data: { available: false } };
    });
    const app = { ...methods, platformInfo: { update_channel: 'self' }, updatePreference: 'automatic' };
    await app.checkForUpdates();
    assert.equal(command, 'check_for_updates');
});
