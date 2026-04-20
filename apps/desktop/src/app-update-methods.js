function resolveFallbackTauriInvoke() {
    const tauriGlobal = window.__TAURI__;

    if (!tauriGlobal) {
        return null;
    }

    return tauriGlobal.core?.invoke || tauriGlobal.tauri?.invoke || tauriGlobal.invoke || null;
}

async function invoke(command, args = {}) {
    const invokeFn = window.HybridCipherTauri?.invoke || resolveFallbackTauriInvoke();

    if (!invokeFn) {
        console.error('Tauri API is not available yet. Are you running inside the Tauri shell?');
        throw new Error('Tauri API is not available');
    }

    return invokeFn(command, args);
}

window.HybridCipherAppUpdateMethods = {
    async checkForUpdates() {
        if (this.updatePreference === 'manual') return;

        try {
            const result = await invoke('check_for_updates');
            if (!result?.success || !result?.data?.available) {
                this.availableUpdate = null;
                this.updateSettingsBadge();
                return;
            }

            const { version, notes } = result.data;
            this.availableUpdate = { version, notes };
            this.updateSettingsBadge();

            if (this.updatePreference === 'automatic') {
                this.showUpdateBanner(version, notes);
            }
        } catch (e) {
            console.debug('Update check skipped:', e);
        }
    },

    async checkForUpdatesManual() {
        const statusEl = document.getElementById('settingsUpdateStatus');
        if (statusEl) statusEl.innerHTML = '<span class="update-status-checking">Checking for updates…</span>';

        try {
            const result = await invoke('check_for_updates');
            if (!result?.success) {
                this.availableUpdate = null;
                this.updateSettingsBadge();
                if (statusEl) statusEl.innerHTML = `<span class="update-status-error">${this.escapeHtml(result?.error || 'Check failed')}</span>`;
                return;
            }
            if (!result.data.available) {
                this.availableUpdate = null;
                this.updateSettingsBadge();
                this.renderSettingsUpdateStatus();
                return;
            }

            const { version, notes } = result.data;
            this.availableUpdate = { version, notes };
            this.updateSettingsBadge();
            this.renderSettingsUpdateStatus();
        } catch (e) {
            if (statusEl) statusEl.innerHTML = '<span class="update-status-error">Update check failed</span>';
        }
    },

    updateSettingsBadge() {
        const badge = document.getElementById('settingsUpdateBadge');
        if (!badge) return;
        if (this.availableUpdate) {
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
    },

    renderSettingsUpdateStatus() {
        const statusEl = document.getElementById('settingsUpdateStatus');
        if (!statusEl) return;

        if (this.availableUpdate) {
            statusEl.innerHTML = `
                <div class="update-status-available">
                    <span>Update available: v${this.escapeHtml(this.availableUpdate.version)}</span>
                    <button class="btn btn-primary" id="settingsInstallUpdateBtn" style="padding:4px 12px;font-size:12px">
                        Install &amp; Restart
                    </button>
                </div>
            `;
            document.getElementById('settingsInstallUpdateBtn')?.addEventListener('click', async () => {
                await this.startUpdateInstallFlow();
            });
        } else {
            statusEl.innerHTML = '<span class="update-status-current">✓ You\'re up to date</span>';
        }
    },

    showUpdateBanner(version, notes) {
        document.getElementById('updateBanner')?.remove();

        const banner = document.createElement('div');
        banner.id = 'updateBanner';
        banner.style.cssText = [
            'position:fixed', 'bottom:20px', 'right:20px', 'z-index:9999',
            'background:var(--color-surface, #1e293b)', 'border:1px solid var(--color-primary, #6366f1)',
            'border-radius:12px', 'padding:16px 20px', 'max-width:340px',
            'box-shadow:0 8px 32px rgba(0,0,0,0.4)', 'color:var(--color-text, #f1f5f9)',
            'font-size:14px', 'line-height:1.5',
        ].join(';');

        banner.innerHTML = `
            <div style="display:flex;align-items:flex-start;gap:12px">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" style="flex-shrink:0;margin-top:2px;color:#6366f1">
                    <path stroke="currentColor" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
                </svg>
                <div style="flex:1">
                    <div style="font-weight:600;margin-bottom:4px">Update available — v${this.escapeHtml(version)}</div>
                    ${notes ? `<div style="opacity:0.7;font-size:12px;margin-bottom:10px">${this.escapeHtml(notes)}</div>` : ''}
                    <div style="display:flex;gap:8px;margin-top:8px">
                        <button id="updateInstallBtn" style="background:#6366f1;color:#fff;border:none;border-radius:6px;padding:6px 14px;cursor:pointer;font-size:13px;font-weight:500">
                            Install &amp; Restart
                        </button>
                        <button id="updateDismissBtn" style="background:transparent;color:inherit;border:1px solid rgba(255,255,255,0.15);border-radius:6px;padding:6px 14px;cursor:pointer;font-size:13px">
                            Later
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(banner);

        document.getElementById('updateDismissBtn').addEventListener('click', () => banner.remove());
        document.getElementById('updateInstallBtn').addEventListener('click', async () => {
            await this.startUpdateInstallFlow();
            banner.remove();
        });
    },

    showUpdateProgressModal() {
        const modal = document.getElementById('updateProgressModal');
        if (!modal) return;
        modal.style.display = 'flex';
        modal.classList.remove('hidden');
    },

    hideUpdateProgressModal() {
        const modal = document.getElementById('updateProgressModal');
        if (!modal) return;
        modal.style.display = 'none';
        modal.classList.add('hidden');
    },

    updateUpdateProgressUi({ text, percent, meta }) {
        const textEl = document.getElementById('updateProgressText');
        const fillEl = document.getElementById('updateProgressFill');
        const metaEl = document.getElementById('updateProgressMeta');
        if (textEl && typeof text === 'string') textEl.textContent = text;
        if (fillEl && typeof percent === 'number') {
            const clamped = Math.max(0, Math.min(100, percent));
            fillEl.style.width = `${clamped}%`;
        }
        if (metaEl && typeof meta === 'string') metaEl.textContent = meta;
    },

    showUpdateRestartModal() {
        const modal = document.getElementById('updateRestartModal');
        if (!modal) return;
        this.updateRestartRemainingSecs = 15;
        this.updateRestartCountdownUi();
        modal.style.display = 'flex';
        modal.classList.remove('hidden');
        if (this.updateRestartCountdownTimer) {
            clearInterval(this.updateRestartCountdownTimer);
        }
        this.updateRestartCountdownTimer = setInterval(() => {
            this.updateRestartRemainingSecs -= 1;
            this.updateRestartCountdownUi();
            if (this.updateRestartRemainingSecs <= 0) {
                clearInterval(this.updateRestartCountdownTimer);
                this.updateRestartCountdownTimer = null;
                this.triggerAppRestart();
            }
        }, 1000);
    },

    hideUpdateRestartModal() {
        const modal = document.getElementById('updateRestartModal');
        if (modal) {
            modal.style.display = 'none';
            modal.classList.add('hidden');
        }
        if (this.updateRestartCountdownTimer) {
            clearInterval(this.updateRestartCountdownTimer);
            this.updateRestartCountdownTimer = null;
        }
    },

    updateRestartCountdownUi() {
        const countdownEl = document.getElementById('updateRestartCountdown');
        if (!countdownEl) return;
        const secs = Math.max(0, this.updateRestartRemainingSecs);
        countdownEl.textContent = `Restarting automatically in ${secs}s...`;
    },

    formatBytes(bytes) {
        if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        let value = bytes;
        let idx = 0;
        while (value >= 1024 && idx < units.length - 1) {
            value /= 1024;
            idx += 1;
        }
        return `${value.toFixed(idx === 0 ? 0 : 1)} ${units[idx]}`;
    },

    handleUpdaterProgressEvent(payload) {
        if (!payload || typeof payload !== 'object') return;
        const phase = payload.phase || '';
        if (phase === 'starting') {
            this.showUpdateProgressModal();
            this.updateUpdateProgressUi({
                text: payload.message || 'Preparing update...',
                percent: 0,
                meta: '0%'
            });
            return;
        }

        if (phase === 'downloading') {
            this.showUpdateProgressModal();
            const percent = Number.isFinite(payload.percent) ? payload.percent : 0;
            const downloaded = Number.isFinite(payload.downloaded) ? payload.downloaded : 0;
            const total = Number.isFinite(payload.total) ? payload.total : 0;
            const meta = total > 0
                ? `${Math.round(percent)}% (${this.formatBytes(downloaded)} / ${this.formatBytes(total)})`
                : `${this.formatBytes(downloaded)} downloaded`;
            this.updateUpdateProgressUi({
                text: payload.message || 'Downloading update...',
                percent,
                meta
            });
            return;
        }

        if (phase === 'installing') {
            this.showUpdateProgressModal();
            this.updateUpdateProgressUi({
                text: payload.message || 'Installing update...',
                percent: 100,
                meta: 'Finalizing install...'
            });
            return;
        }

        if (phase === 'installed') {
            this.updateUpdateProgressUi({
                text: payload.message || 'Update installed.',
                percent: 100,
                meta: 'Ready to restart'
            });
            return;
        }

        if (phase === 'error') {
            this.hideUpdateProgressModal();
            this.showNotification(payload.message || 'Update installation failed.', 'error');
        }
    },

    async startUpdateInstallFlow() {
        if (this.updateInstallInProgress) {
            return;
        }
        this.updateInstallInProgress = true;
        this.hideUpdateRestartModal();
        this.showUpdateProgressModal();
        this.updateUpdateProgressUi({
            text: 'Preparing update...',
            percent: 0,
            meta: 'Starting...'
        });

        try {
            const result = await invoke('install_update');
            if (!result?.success) {
                throw new Error(result?.error || 'Update install failed');
            }
            this.hideUpdateProgressModal();
            this.showNotification(result?.data || 'Update installed.', 'success');
            this.showUpdateRestartModal();
        } catch (e) {
            this.hideUpdateProgressModal();
            this.showNotification(`Update installation failed: ${e?.message || e}`, 'error');
            throw e;
        } finally {
            this.updateInstallInProgress = false;
            this.renderSettingsUpdateStatus();
        }
    },

    async triggerAppRestart() {
        const btn = document.getElementById('updateRestartNowBtn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Restarting...';
        }
        try {
            const result = await invoke('restart_application');
            if (!result?.success) {
                throw new Error(result?.error || 'Failed to restart application');
            }
        } catch (e) {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Restart now';
            }
            this.showNotification(`Restart failed: ${e?.message || e}`, 'error');
        }
    },
};
