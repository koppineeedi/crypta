/**
 * Privacy-Preserving Password Breach Exposure Checker
 * Uses Have I Been Pwned (HIBP) k-Anonymity API (SHA-1 prefix matching).
 * Plaintext passwords and full hashes are NEVER transmitted over the network.
 */

import { SECURITY_CONFIG } from '../crypto/securityConfig.js';

function getCrypto() {
    if (typeof window !== 'undefined' && window.crypto) {
        return window.crypto;
    }
    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
        return globalThis.crypto;
    }
    throw new Error('Web Crypto API is not supported in this environment.');
}

export async function checkPasswordBreach(password) {
    if (!password) {
        return {
            status: 'NOT_CHECKED',
            count: 0,
            message: 'No password provided for breach check.'
        };
    }

    try {
        const cryptoObj = getCrypto();
        const encoder = new TextEncoder();
        const data = encoder.encode(password);

        // 1. Calculate SHA-1 hash locally in browser
        const hashBuffer = await cryptoObj.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const sha1Hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

        const prefix = sha1Hex.substring(0, SECURITY_CONFIG.HIBP_PREFIX_LENGTH);
        const suffix = sha1Hex.substring(SECURITY_CONFIG.HIBP_PREFIX_LENGTH);

        // 2. Query k-anonymity API using 5-character prefix only
        const response = await fetch(`${SECURITY_CONFIG.HIBP_API_URL}${prefix}`, {
            method: 'GET',
            headers: {
                'Accept': 'text/plain'
            }
        });

        if (!response.ok) {
            return {
                status: 'UNAVAILABLE',
                count: 0,
                message: 'Breach exposure check is currently unavailable. No safety conclusion can be made.',
                privacyNote: 'Crypta never sends your plaintext password to external services.'
            };
        }

        const body = await response.text();
        const lines = body.split('\n');

        for (const line of lines) {
            const [lineSuffix, countStr] = line.trim().split(':');
            if (lineSuffix && lineSuffix.toUpperCase() === suffix) {
                const count = parseInt(countStr, 10) || 1;
                return {
                    status: 'FOUND',
                    count: count,
                    message: `⚠ Found in known breach datasets (${count.toLocaleString()} exposures). Do not use this password.`,
                    privacyNote: 'Crypta derived the k-anonymity prefix locally. Plaintext password was never transmitted.'
                };
            }
        }

        return {
            status: 'NOT_FOUND',
            count: 0,
            message: '✓ No match found in known breach datasets.',
            privacyNote: 'Crypta derived the k-anonymity prefix locally. Plaintext password was never transmitted.'
        };
    } catch (error) {
        return {
            status: 'UNAVAILABLE',
            count: 0,
            message: 'Breach exposure check is currently unavailable. No safety conclusion can be made.',
            privacyNote: 'Crypta never sends your plaintext password to external services.'
        };
    }
}
