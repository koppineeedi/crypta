/**
 * Crypta Password Reuse Checker UI Controller
 */

import { PasswordReuseTracker } from '../password/reuseDetection.js';
import { escapeHtml } from '../utils/formatting.js';

export function initReuseUI() {
    const tracker = new PasswordReuseTracker();

    const accountInput = document.getElementById('reuse-account-input');
    const pwdInput = document.getElementById('reuse-password-input');
    const btnAdd = document.getElementById('btn-add-reuse-entry');
    const tableBody = document.getElementById('reuse-table-body');
    const alertBox = document.getElementById('reuse-alert-box');

    function renderTable() {
        const analysis = tracker.analyze();

        if (tableBody) {
            if (tracker.entries.length === 0) {
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="3" class="text-center text-muted py-3">No account passwords added to session. Add accounts above to test for reuse vulnerability.</td>
                    </tr>
                `;
            } else {
                tableBody.innerHTML = tracker.entries.map((entry, idx) => `
                    <tr>
                        <td class="font-medium">${escapeHtml(entry.account)}</td>
                        <td>••••••••••••</td>
                        <td class="text-right">
                            <button type="button" class="btn-sm btn-outline-danger" data-remove-id="${entry.id}">Remove</button>
                        </td>
                    </tr>
                `).join('');

                // Attach remove click listeners
                tableBody.querySelectorAll('[data-remove-id]').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const id = btn.getAttribute('data-remove-id');
                        tracker.removeEntry(id);
                        renderTable();
                    });
                });
            }
        }

        if (alertBox) {
            if (analysis.hasReuse) {
                const groupsHtml = analysis.reusedGroups.map(g => `
                    <div class="mt-2 pl-3 border-left-danger">
                        <strong>Identical password used across ${g.count} accounts:</strong>
                        <div>• ${g.accounts.map(a => escapeHtml(a)).join('<br>• ')}</div>
                    </div>
                `).join('');

                alertBox.innerHTML = `
                    <div class="alert alert-danger">
                        <h4>⚠ Password Reuse Detected</h4>
                        <p>${escapeHtml(analysis.recommendation)}</p>
                        ${groupsHtml}
                    </div>
                `;
            } else if (tracker.entries.length > 1) {
                alertBox.innerHTML = `
                    <div class="alert alert-success">
                        <h4>✓ All Account Passwords Unique</h4>
                        <p>${escapeHtml(analysis.recommendation)}</p>
                    </div>
                `;
            } else {
                alertBox.innerHTML = `
                    <div class="alert alert-info">
                        <p>Add 2 or more accounts to analyze password reuse vulnerabilities.</p>
                    </div>
                `;
            }
        }
    }

    if (btnAdd) {
        btnAdd.addEventListener('click', (e) => {
            e.preventDefault();
            const account = accountInput ? accountInput.value : '';
            const password = pwdInput ? pwdInput.value : '';

            if (!account || !password) {
                alert('Please enter both an account name and a password.');
                return;
            }

            tracker.addEntry(account, password);
            if (accountInput) accountInput.value = '';
            if (pwdInput) pwdInput.value = '';

            renderTable();
        });
    }

    renderTable();
}
