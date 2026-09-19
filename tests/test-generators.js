/**
 * Password & Passphrase Generator Unit Test Suite
 */

import assert from 'node:assert';
import { test, describe } from 'node:test';
import { generateSecurePassword } from '../src/password/generator.js';
import { generatePassphrase } from '../src/password/passphraseGenerator.js';

describe('Password Generators', () => {
    test('Password Generator respects length and character set constraints', () => {
        const pwd = generateSecurePassword({
            length: 24,
            includeUppercase: true,
            includeLowercase: true,
            includeNumbers: true,
            includeSymbols: true,
            avoidAmbiguous: true
        });

        assert.strictEqual(pwd.length, 24);
        assert.ok(/[A-Z]/.test(pwd), 'Must contain uppercase');
        assert.ok(/[a-z]/.test(pwd), 'Must contain lowercase');
        assert.ok(/[0-9]/.test(pwd), 'Must contain digit');
        assert.ok(/[^A-Za-z0-9]/.test(pwd), 'Must contain symbol');
        assert.ok(!/[l1IO0]/.test(pwd), 'Must avoid ambiguous characters');
    });

    test('Passphrase Generator generates requested word count and separator', () => {
        const pass = generatePassphrase({
            wordCount: 5,
            separator: '-',
            includeNumber: false,
            includeSymbol: false
        });

        const words = pass.split('-');
        assert.strictEqual(words.length, 5);
        words.forEach(w => assert.ok(w.length > 2));
    });
});
