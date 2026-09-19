/**
 * Local Session-Based Password Reuse Detector
 * Detects identical or normalized passwords reused across multiple user accounts.
 * Operates strictly in transient local memory.
 */

export class PasswordReuseTracker {
    constructor() {
        this.entries = []; // Array of { id, account, password }
    }

    addEntry(accountName, password) {
        if (!accountName || !password) {
            throw new Error('Both account name and password are required.');
        }

        const newId = Date.now().toString(36) + Math.random().toString(36).substring(2, 6);
        this.entries.push({
            id: newId,
            account: accountName.trim(),
            password: password
        });

        return this.analyze();
    }

    removeEntry(id) {
        this.entries = this.entries.filter(e => e.id !== id);
        return this.analyze();
    }

    clear() {
        this.entries = [];
        return this.analyze();
    }

    analyze() {
        const passwordMap = new Map(); // password -> array of account names

        for (const entry of this.entries) {
            const pwd = entry.password;
            if (!passwordMap.has(pwd)) {
                passwordMap.set(pwd, []);
            }
            passwordMap.get(pwd).push(entry.account);
        }

        const reusedAccounts = []; // Array of { password, accounts }
        for (const [pwd, accounts] of passwordMap.entries()) {
            if (accounts.length > 1) {
                reusedAccounts.push({
                    accounts,
                    count: accounts.length
                });
            }
        }

        const totalAccounts = this.entries.length;
        const hasReuse = reusedAccounts.length > 0;

        return {
            totalAccounts,
            hasReuse,
            reusedGroups: reusedAccounts,
            entries: this.entries.map(e => ({ id: e.id, account: e.account })),
            recommendation: hasReuse
                ? '⚠ Password Reuse Detected! Reusing passwords across accounts significantly increases vulnerability to credential stuffing attacks. Use a unique password for every service.'
                : '✓ No password reuse detected among added accounts in this session.'
        };
    }
}
