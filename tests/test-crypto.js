/**
 * Cryptography Integration Test Suite
 */

import assert from 'node:assert';
import { test, describe } from 'node:test';
import { encryptFile } from '../src/crypto/encryption.js';
import { decryptFile } from '../src/crypto/decryption.js';
import { SECURITY_CONFIG } from '../src/crypto/securityConfig.js';

describe('Web Crypto AES-256-GCM File Security', () => {
    test('Encrypt and decrypt roundtrip restores exact original payload and filename', async () => {
        const originalName = 'secret_document.pdf';
        const originalText = 'CONFIDENTIAL: Financial Audit Report 2026';
        const encoder = new TextEncoder();
        const decoder = new TextDecoder();
        const payloadBuffer = encoder.encode(originalText).buffer;

        const password = 'SuperSecurePassword123!';

        // 1. Encrypt
        const encryptedPacket = await encryptFile(payloadBuffer, originalName, password);
        assert.ok(encryptedPacket instanceof ArrayBuffer);
        assert.ok(encryptedPacket.byteLength > payloadBuffer.byteLength);

        // 2. Decrypt
        const decryptedResult = await decryptFile(encryptedPacket, password);
        assert.strictEqual(decryptedResult.originalName, originalName);

        const restoredText = decoder.decode(decryptedResult.decryptedBuffer);
        assert.strictEqual(restoredText, originalText);
    });

    test('Encrypting identical payload produces unique salt and IV every time', async () => {
        const payload = new TextEncoder().encode('Test Data Payload').buffer;
        const pwd = 'StaticPassword123!';

        const packet1 = new Uint8Array(await encryptFile(payload, 'test.txt', pwd));
        const packet2 = new Uint8Array(await encryptFile(payload, 'test.txt', pwd));

        // Salt starts after Magic (6) + Filename Len (2) + Filename (8) = 16
        const salt1 = packet1.slice(16, 16 + SECURITY_CONFIG.SALT_LENGTH);
        const salt2 = packet2.slice(16, 16 + SECURITY_CONFIG.SALT_LENGTH);

        const iv1 = packet1.slice(16 + SECURITY_CONFIG.SALT_LENGTH, 16 + SECURITY_CONFIG.SALT_LENGTH + SECURITY_CONFIG.IV_LENGTH);
        const iv2 = packet2.slice(16 + SECURITY_CONFIG.SALT_LENGTH, 16 + SECURITY_CONFIG.SALT_LENGTH + SECURITY_CONFIG.IV_LENGTH);

        assert.notDeepStrictEqual(salt1, salt2, 'Salts must be cryptographically unique per encryption');
        assert.notDeepStrictEqual(iv1, iv2, 'IVs must be cryptographically unique per encryption');
    });

    test('Decryption fails with incorrect password', async () => {
        const payload = new TextEncoder().encode('Sensitive Payload').buffer;
        const packet = await encryptFile(payload, 'data.txt', 'CorrectPassword123!');

        await assert.rejects(
            async () => {
                await decryptFile(packet, 'WrongPassword456!');
            },
            /Unable to decrypt this file/
        );
    });

    test('Decryption fails with corrupted ciphertext', async () => {
        const payload = new TextEncoder().encode('Intact Payload').buffer;
        const packet = await encryptFile(payload, 'file.bin', 'Password123!');

        const view = new Uint8Array(packet);
        // Flip a byte in the ciphertext payload near the end
        view[view.length - 5] ^= 0xFF;

        await assert.rejects(
            async () => {
                await decryptFile(view.buffer, 'Password123!');
            },
            /Unable to decrypt this file/
        );
    });
});
