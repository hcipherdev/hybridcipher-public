// Tests reconnectedMountJobs() in src/auto-mount-utils.js and handleMountsReconnected() in src/app.js: mounts reconnected after a restart refresh the mount lists silently, and ones that could not be reconnected are reported once.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const scope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/auto-mount-utils.js', import.meta.url), 'utf8'), scope);
const { reconnectedMountJobs } = scope.HybridCipherAutoMountUtils;
const plain = value => JSON.parse(JSON.stringify(value));

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
const begin = source.indexOf('    handleMountsReconnected(');
const finish = source.indexOf('    reportMountBatch(', begin);
assert.ok(begin >= 0 && finish > begin, 'Cannot extract handleMountsReconnected');

function appWith() {
    const App = Function('reconnectedMountJobsValue', `return class { ${source.slice(begin, finish)} }`)(reconnectedMountJobs);
    const app = new App();
    const calls = { refreshes: 0, reports: [] };
    Object.assign(app, {
        scheduleMountListsRefresh() { calls.refreshes += 1; },
        reportMountBatch(jobs, attention, options) { calls.reports.push({ jobs: plain(jobs), attention, options }); },
    });
    return { app, calls };
}

test('reconnectedMountJobs turns the event into mounted and failed jobs', () => {
    assert.deepEqual(plain(reconnectedMountJobs({
        reconnected: ['a'],
        failed: [{ root_id: 'b', name: 'Docs', error: 'provider did not start' }, { root_id: 'c' }],
    })), [
        { root_id: 'a', name: 'a', status: 'ready' },
        { root_id: 'b', name: 'Docs', status: 'failed', error: 'provider did not start' },
        { root_id: 'c', name: 'c', status: 'failed', error: 'This folder could not be reconnected.' },
    ]);
    assert.deepEqual(plain(reconnectedMountJobs({})), [], 'a malformed event yields nothing');
});

test('a clean reconnect only refreshes the mount lists', () => {
    const { app, calls } = appWith();
    app.handleMountsReconnected({ reconnected: ['a', 'b'], failed: [] });
    assert.equal(calls.refreshes, 1);
    assert.deepEqual(calls.reports, [], 'no notification when every mount came back');
});

test('a folder that could not be reconnected is reported once, with the reconnected ones counted', () => {
    const { app, calls } = appWith();
    app.handleMountsReconnected({ reconnected: ['a'], failed: [{ root_id: 'b', name: 'Docs', error: 'boom' }] });
    assert.equal(calls.refreshes, 1);
    assert.equal(calls.reports.length, 1);
    assert.deepEqual(calls.reports[0].jobs.map(job => [job.root_id, job.status]), [['a', 'ready'], ['b', 'failed']]);
    assert.equal(calls.reports[0].options.label, 'Reconnect');
});
