/**
 * Password Security Analyzer Unit Test Suite
 */

import assert from 'node:assert';
import { test, describe } from 'node:test';
import { analyzePassword } from '../src/password/analyzer.js';

describe('Password Security Engine', () => {
    test('Flags empty password as Critical (0/100)', () => {
        const res = analyzePassword('');
        assert.strictEqual(res.score, 0);
        assert.strictEqual(res.rating, 'Critical');
    });

    test('Flags common blacklisted passwords like "password123"', () => {
        const res = analyzePassword('password123');
        assert.ok(res.score < 40, `Score should be weak for common password, got ${res.score}`);
        assert.ok(res.weaknesses.some(w => w.includes('common')));
    });

    test('Detects keyboard walks like "qwerty123"', () => {
        const res = analyzePassword('qwerty123');
        assert.ok(res.weaknesses.some(w => w.toLowerCase().includes('keyboard') || w.toLowerCase().includes('sequential')));
    });

    test('Scores long random passphrase as Very Strong (85+)', () => {
        const res = analyzePassword('river-copper-lantern-orbit-mango');
        assert.ok(res.score >= 85, `Passphrase score should be >= 85, got ${res.score}`);
        assert.strictEqual(res.rating, 'Very Strong');
        assert.ok(res.rawGuesses > 1e12);
    });

    test('Evaluates 3 attack model scenarios', () => {
        const res = analyzePassword('Complex#Password2026!Secure');
        assert.ok(res.attackResistance.onlineThrottled);
        assert.ok(res.attackResistance.offlineFastHash);
        assert.ok(res.attackResistance.offlineSlowHash);

        assert.strictEqual(res.attackResistance.onlineThrottled.rating, 'VERY HIGH');
    });
});
