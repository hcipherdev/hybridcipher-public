// Tests mountPreparingLabel() and the preparingLabel of mounted rows in buildMountCenterModel() in src/ui-utils.js.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const uiScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
const { buildMountCenterModel, mountPreparingLabel } = uiScope.HybridCipherUiUtils;

const folder = (rootId, mount) => ({
    root_id: rootId, name: rootId, path: `/x/${rootId}`, group_id: 'g', group_name: 'Personal',
    workspace: 'personal', can_mount: true, auto_mount: false, mount,
});
const mounted = (rootId, syncStatus) => folder(rootId, {
    root_id: rootId, mountpoint: `/cloud/${rootId}`, backend: 'macos-file-provider', availability: 'ready',
    sync_status: syncStatus,
});
const rowsOf = model => Object.fromEntries(model.sections.flatMap(section => section.folders).map(row => [row.rootId, row]));

test('a mount still decrypting its files shows how far it is', () => {
    assert.equal(
        mountPreparingLabel({ preparing_files: { processed: 12400, total: 100000 } }),
        'Preparing files 12,400 of 100,000 · 12% · files open on demand'
    );
    assert.equal(
        mountPreparingLabel({ preparing_files: { processed: 100000, total: 100000 } }),
        'Preparing files 100,000 of 100,000 · 100% · files open on demand'
    );
});

test('nothing is shown once the first pass is done or before it has a count', () => {
    assert.equal(mountPreparingLabel({}), '');
    assert.equal(mountPreparingLabel(null), '');
    assert.equal(mountPreparingLabel({ preparing_files: { processed: 0, total: 0 } }), '');
});

test('only mounted rows carry the preparation label', () => {
    const rows = rowsOf(buildMountCenterModel({
        folders: [
            mounted('busy', { safe_to_unmount: true, preparing_files: { processed: 5, total: 10 } }),
            mounted('done', { safe_to_unmount: true }),
            folder('off', null),
        ],
    }));

    assert.equal(rows.busy.statusLabel, 'Mounted');
    assert.equal(rows.busy.preparingLabel, 'Preparing files 5 of 10 · 50% · files open on demand');
    assert.equal(rows.done.preparingLabel, '');
    assert.equal(rows.off.preparingLabel, '');
});
