/**
 * Web Crypto AES-GCM 256-bit File Decryption
 */

import { SECURITY_CONFIG } from './securityConfig.js';
import { deriveKey } from './keyDerivation.js';

function getCrypto() {
    if (typeof window !== 'undefined' && window.crypto) {
        return window.crypto;
    }
    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
        return globalThis.crypto;
    }
    throw new Error('Web Crypto API is not supported in this environment.');
}

export async function decryptFile(fileOrBuffer, password) {
    if (!password) {
        throw new Error('Password is required for file decryption.');
    }

    let fileData;
    if (fileOrBuffer instanceof File || fileOrBuffer instanceof Blob) {
        fileData = await fileOrBuffer.arrayBuffer();
    } else if (fileOrBuffer instanceof ArrayBuffer) {
        fileData = fileOrBuffer;
    } else if (ArrayBuffer.isView(fileOrBuffer)) {
        fileData = fileOrBuffer.buffer.slice(fileOrBuffer.byteOffset, fileOrBuffer.byteOffset + fileOrBuffer.byteLength);
    } else {
        throw new Error('Unsupported file payload format.');
    }

    const minHeaderLength = SECURITY_CONFIG.MAGIC_HEADER.length + 2 + SECURITY_CONFIG.SALT_LENGTH + SECURITY_CONFIG.IV_LENGTH;
    if (fileData.byteLength < minHeaderLength) {
        throw new Error('This file format or encrypted payload is not recognized by Crypta.');
    }

    const view = new Uint8Array(fileData);
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    const magicBytes = encoder.encode(SECURITY_CONFIG.MAGIC_HEADER);

    let offset = 0;

    // 1. Validate Magic Header ("CRYPTA")
    for (let i = 0; i < magicBytes.length; i++) {
        if (view[i] !== magicBytes[i]) {
            throw new Error('This file format or encrypted payload is not recognized by Crypta.');
        }
    }
    offset += magicBytes.length;

    // 2. Read Filename Length (Uint16 Big-Endian)
    const dv = new DataView(fileData);
    const fileNameLength = dv.getUint16(offset, false);
    offset += 2;

    if (offset + fileNameLength + SECURITY_CONFIG.SALT_LENGTH + SECURITY_CONFIG.IV_LENGTH > fileData.byteLength) {
        throw new Error('This file format or encrypted payload is corrupted.');
    }

    // 3. Read Filename
    const fileNameBytes = view.slice(offset, offset + fileNameLength);
    const originalName = decoder.decode(fileNameBytes) || 'decrypted_file';
    offset += fileNameLength;

    // 4. Read Salt
    const salt = view.slice(offset, offset + SECURITY_CONFIG.SALT_LENGTH);
    offset += SECURITY_CONFIG.SALT_LENGTH;

    // 5. Read IV
    const iv = view.slice(offset, offset + SECURITY_CONFIG.IV_LENGTH);
    offset += SECURITY_CONFIG.IV_LENGTH;

    // 6. Read Ciphertext
    const ciphertext = fileData.slice(offset);

    // 7. Derive Key & Decrypt
    const cryptoObj = getCrypto();
    const aesKey = await deriveKey(password, salt, ['decrypt']);

    try {
        const decryptedBuffer = await cryptoObj.subtle.decrypt(
            {
                name: SECURITY_CONFIG.KEY_ALGORITHM,
                iv: iv
            },
            aesKey,
            ciphertext
        );

        return {
            decryptedBuffer,
            originalName
        };
    } catch (e) {
        throw new Error('Unable to decrypt this file. The password may be incorrect or the file may be corrupted.');
    }
}
