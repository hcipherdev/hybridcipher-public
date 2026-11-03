// Clicks through the team-admin flow in the real desktop UI, backed by mock-tauri.js and
// mock-team.js, and saves one screenshot per guide step into ../site/img/team/.
// File names follow the guide's step order; the capture order differs where the demo state needs it.
// Run: node capture-team.js
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const { openApp, shot } = require('./lib');

const OUT = path.resolve(__dirname, '../site/img/team');
const ADMIN = 'maria@northwind.example';

// Closes the progress dialog a finished team action leaves open, if any.
async function closeOperationDialog(page) {
    const close = page.locator('#desktopOperationCloseBtn');
    if (await close.isVisible().catch(() => false)) await close.click();
    await page.waitForTimeout(400);
}

async function openGroup(page, name) {
    await page.click(`#sidebarTeamNav >> text=${name}`);
    await page.waitForTimeout(1200);
    await closeOperationDialog(page);
}

(async () => {
    fs.mkdirSync(OUT, { recursive: true });
    const browser = await chromium.launch();
    const page = await openApp(browser, {
        scripts: ['mock-team.js'],
        state: {
            signedIn: true,
            email: ADMIN,
            pickFolder: '/Users/maria/Northwind/Marketing',
            // Daniel signed in on a new computer and is waiting for approval.
            team: { pending: [{ key: 'daniel', device: 'Daniel’s Mac mini', since: new Date(Date.now() - 40 * 60 * 1000).toISOString() }] },
        },
        storage: {
            hybridcipher_welcome_modal_dismissed_v1: 'true',
            [`hybridcipher_workspace_${encodeURIComponent(ADMIN)}`]: 'team',
        },
    });
    await page.waitForTimeout(1300);
    await page.evaluate(() => window.app.refreshWorkspaceHomeStatus());

    // 1. Team overview, opened from the workspace menu.
    await shot(page, OUT, '01-overview', '#workspaceSelector');

    // 2. Approve a new device from the To do list.
    await shot(page, OUT, '08-approve-device', '#teamTodoList [data-todo-action]');
    await page.click('#teamTodoList [data-todo-action]');
    await page.waitForTimeout(1000);
    await closeOperationDialog(page);

    // 3. Invite someone new to the Team and choose their groups. Done before creating the
    // Marketing group: the invite dialog's group list is cached for a minute.
    await page.click('#sidebarMembersBtn');
    await page.waitForTimeout(800);
    await page.click('#membersInviteBtn');
    await page.fill('#teamInviteEmail', 'lena@northwind.example');
    await page.check('#teamInviteGroups label:has-text("Design") input');
    await shot(page, OUT, '05-invite', '#teamInviteModal .modal-content');
    await page.click('#teamInviteSubmitBtn');
    await page.waitForTimeout(800);
    await shot(page, OUT, '06-invite-code', '#teamInviteCode');
    await page.click('#teamInviteCancelBtn');
    await page.waitForTimeout(400);

    // 4. Create a group.
    await page.click('#sidebarOverviewBtn');
    await page.waitForTimeout(600);
    await page.click('#homeNewGroupBtn');
    await page.fill('#createGroupName', 'Marketing');
    await page.fill('#createGroupDescription', 'Campaign plans and press kits');
    await shot(page, OUT, '02-create-group', '#submitCreateGroupBtn');
    await page.click('#submitCreateGroupBtn');
    await page.waitForSelector('#submitCreateGroupBtn:has-text("Ready")');
    await page.click('#closeCreateGroupModalBtn');
    await page.waitForTimeout(600);

    // 5. Add an existing member to the group.
    await openGroup(page, 'Marketing');
    await page.click('#adminAddMemberBtn');
    await page.fill('#groupMemberEmail', 'tom@northwind.example');
    await shot(page, OUT, '03-add-person', '#groupMemberAddBtn');
    await page.click('#groupMemberAddBtn');
    await page.waitForTimeout(1200);
    await closeOperationDialog(page);
    await shot(page, OUT, '04-group-people', '#adminPeopleList');

    // 6. Protect the group's shared folder.
    await page.click('#addFolderBtn');
    await page.waitForSelector('#actionPromptModal[style*="flex"]');
    await shot(page, OUT, '07-protect-folder', '#actionPromptPrimaryBtn');
    await page.click('#actionPromptPrimaryBtn');
    await page.waitForTimeout(1200);
    await closeOperationDialog(page);

    // 7. Members & devices across the Team.
    await page.click('#sidebarMembersBtn');
    await page.waitForTimeout(1000);
    await shot(page, OUT, '09-members', '#membersFilter');

    // 8. Remove someone's access to a group (keys rotate in the same step).
    await openGroup(page, 'Finance');
    await page.click('#adminPeopleList [data-people-action="remove"] >> nth=-1');
    await page.waitForSelector('#actionPromptModal[style*="flex"]');
    await shot(page, OUT, '10-remove-access', '#actionPromptPrimaryBtn');
    await page.click('#actionPromptSecondaryBtn');

    await browser.close();
})();
