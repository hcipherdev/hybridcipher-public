// Manual CLI command list used by the command palette.
// Edit this file to add or adjust commands.
window.hybridcipherCliCommands = [
    {
        command: 'login',
        description: 'Log in to HybridCipher',
        keywords: ['auth', 'account', 'session']
    },
    {
        command: 'register',
        description: 'Register a new user',
        keywords: ['auth', 'account', 'signup']
    },
    {
        command: 'forgot-password',
        description: 'Start password recovery flow',
        keywords: ['auth', 'password', 'reset']
    },
    {
        command: 'password-reset',
        description: 'Reset account password',
        keywords: ['auth', 'password', 'reset']
    },
    {
        command: 'change-password',
        description: 'Change your password',
        keywords: ['auth', 'password']
    },
    {
        command: 'keystore-status',
        description: 'Check device keystore status',
        keywords: ['keystore', 'device', 'keys']
    },
    {
        command: 'logout',
        description: 'Log out of the current session',
        keywords: ['auth', 'session']
    },
    {
        command: 'current-user',
        description: 'Show the current logged-in user',
        keywords: ['auth', 'session']
    },
    {
        command: 'show-token',
        description: 'Show access token info',
        keywords: ['auth', 'token']
    },
    {
        command: 'health-check',
        description: 'Verify auth and server reachability',
        keywords: ['status', 'server']
    },
    {
        command: 'create-group',
        description: 'Create a new group',
        keywords: ['group', 'groups']
    },
    {
        command: 'rename-group',
        description: 'Rename a group',
        keywords: ['group', 'groups']
    },
    {
        command: 'initialize-group',
        description: 'Initialize group epoch keys',
        keywords: ['group', 'groups']
    },
    {
        command: 'switch-group',
        description: 'Switch the active group',
        keywords: ['group', 'groups']
    },
    {
        command: 'current-group',
        description: 'Show the active group',
        keywords: ['group', 'groups']
    },
    {
        command: 'list-groups',
        description: 'List available groups',
        keywords: ['group', 'groups']
    },
    {
        command: 'delete-group',
        description: 'Delete a group',
        keywords: ['group', 'groups']
    },
    {
        command: 'add-member',
        description: 'Add a member to a group',
        keywords: ['group', 'member', 'invite']
    },
    {
        command: 'remove-member',
        description: 'Remove a member from a group',
        keywords: ['group', 'member']
    },
    {
        command: 'list-members',
        description: 'List group members',
        keywords: ['group', 'member', 'members']
    },
    {
        command: 'process-welcome-messages',
        description: 'Process pending Welcome messages',
        keywords: ['welcome', 'group']
    },
    {
        command: 'generate-welcome',
        description: 'Generate a Welcome payload',
        keywords: ['welcome', 'group']
    },
    {
        command: 'issue-welcome',
        description: 'Issue a Welcome to a device',
        keywords: ['welcome', 'device']
    },
    {
        command: 'pending-devices',
        description: 'List devices pending approval for the current group',
        keywords: ['welcome', 'device', 'pending']
    },
    {
        command: 'devices',
        description: 'Manage devices',
        keywords: ['device', 'devices']
    },
    {
        command: 'remove-device',
        description: 'Remove a device',
        keywords: ['device', 'devices']
    },
    {
        command: 'audit-devices',
        description: 'Audit and prune stale devices',
        keywords: ['device', 'devices', 'audit']
    },
    {
        command: 'encrypt',
        description: 'Encrypt a file',
        keywords: ['file', 'encryption']
    },
    {
        command: 'decrypt',
        description: 'Decrypt a file',
        keywords: ['file', 'decryption']
    },
    {
        command: 'mount',
        description: 'Mount an encrypted folder',
        keywords: ['mount', 'filesystem']
    },
    {
        command: 'unmount',
        description: 'Unmount a folder',
        keywords: ['mount', 'filesystem']
    },
    {
        command: 'rekey',
        description: 'Rekey lifecycle commands',
        keywords: ['rekey', 'group']
    },
    {
        command: 'coverage',
        description: 'Coverage and indexing commands',
        keywords: ['coverage', 'scan', 'audit']
    },
    {
        command: 'pin',
        description: 'Device pinning commands',
        keywords: ['pin', 'trust']
    },
    {
        command: 'server-trust',
        description: 'Server trust management',
        keywords: ['trust', 'server']
    },
    {
        command: 'recovery',
        description: 'Recovery upload and fetch',
        keywords: ['recovery', 'restore']
    },
    {
        command: 'get-epoch-keys',
        description: 'Fetch epoch keys for recovery',
        keywords: ['recovery', 'keys']
    },
    {
        command: 'help',
        description: 'Show CLI help',
        keywords: ['help']
    }
];
