/**
 * Web Crypto Key Derivation Engine (PBKDF2)
 */

import { SECURITY_CONFIG } from './securityConfig.js';

function getCrypto() {
    if (typeof window !== 'undefined' && window.crypto) {
        return window.crypto;
    }
    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
        return globalThis.crypto;
    }
    throw new Error('Web Crypto API is not supported in this environment.');
}

export async function deriveKey(password, salt, usages = ['encrypt', 'decrypt']) {
    const cryptoObj = getCrypto();
    const encoder = new TextEncoder();

    const baseKey = await cryptoObj.subtle.importKey(
        'raw',
        encoder.encode(password),
        SECURITY_CONFIG.KDF_ALGORITHM,
        false,
        ['deriveKey']
    );

    return await cryptoObj.subtle.deriveKey(
        {
            name: SECURITY_CONFIG.KDF_ALGORITHM,
            salt: salt,
            iterations: SECURITY_CONFIG.KDF_ITERATIONS,
            hash: SECURITY_CONFIG.HASH_ALGORITHM
        },
        baseKey,
        {
            name: SECURITY_CONFIG.KEY_ALGORITHM,
            length: SECURITY_CONFIG.KEY_LENGTH
        },
        false,
        usages
    );
}
