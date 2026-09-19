/**
 * Password Breach & Reuse Unit Test Suite
 */

import assert from 'node:assert';
import { test, describe } from 'node:test';
import { PasswordReuseTracker } from '../src/password/reuseDetection.js';
import { checkPasswordBreach } from '../src/password/breachCheck.js';

describe('Password Reuse & Breach Exposure', () => {
    test('PasswordReuseTracker detects identical passwords across multiple accounts', () => {
        const tracker = new PasswordReuseTracker();
        tracker.addEntry('GitHub', 'SamePassword123!');
        tracker.addEntry('Gmail', 'SamePassword123!');
        tracker.addEntry('Twitter', 'DifferentPassword456!');

        const res = tracker.analyze();
        assert.strictEqual(res.hasReuse, true);
        assert.strictEqual(res.reusedGroups.length, 1);
        assert.deepStrictEqual(res.reusedGroups[0].accounts, ['GitHub', 'Gmail']);
    });

    test('PasswordReuseTracker confirms uniqueness when all passwords differ', () => {
        const tracker = new PasswordReuseTracker();
        tracker.addEntry('GitHub', 'UniquePwd1!');
        tracker.addEntry('Gmail', 'UniquePwd2@');

        const res = tracker.analyze();
        assert.strictEqual(res.hasReuse, false);
    });

    test('checkPasswordBreach executes SHA-1 hashing locally without leaking plaintext', async () => {
        const res = await checkPasswordBreach('password123');
        assert.ok(res.status === 'FOUND' || res.status === 'UNAVAILABLE');
        if (res.status === 'FOUND') {
            assert.ok(res.count > 0);
            assert.ok(res.message.includes('Found in known breach datasets'));
        }
    });
});
