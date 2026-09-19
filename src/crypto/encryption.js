/**
 * Web Crypto AES-GCM 256-bit File Encryption
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

export async function encryptFile(fileOrBuffer, fileName, password) {
    if (!password) {
        throw new Error('Password is required for file encryption.');
    }

    let fileData;
    let nameToEncode = fileName || 'encrypted.dat';

    if (fileOrBuffer instanceof File || fileOrBuffer instanceof Blob) {
        fileData = await fileOrBuffer.arrayBuffer();
        if (fileOrBuffer.name) {
            nameToEncode = fileOrBuffer.name;
        }
    } else if (fileOrBuffer instanceof ArrayBuffer) {
        fileData = fileOrBuffer;
    } else if (ArrayBuffer.isView(fileOrBuffer)) {
        fileData = fileOrBuffer.buffer.slice(fileOrBuffer.byteOffset, fileOrBuffer.byteOffset + fileOrBuffer.byteLength);
    } else {
        throw new Error('Invalid input file payload format.');
    }

    const cryptoObj = getCrypto();
    const encoder = new TextEncoder();

    // 1. Generate cryptographically secure random Salt & IV
    const salt = cryptoObj.getRandomValues(new Uint8Array(SECURITY_CONFIG.SALT_LENGTH));
    const iv = cryptoObj.getRandomValues(new Uint8Array(SECURITY_CONFIG.IV_LENGTH));

    // 2. Derive AES-GCM key
    const aesKey = await deriveKey(password, salt, ['encrypt']);

    // 3. Encrypt payload
    const ciphertext = await cryptoObj.subtle.encrypt(
        {
            name: SECURITY_CONFIG.KEY_ALGORITHM,
            iv: iv
        },
        aesKey,
        fileData
    );

    // 4. Construct packet binary format:
    // MAGIC (6) + FILE_LEN (2) + FILE_NAME (utf-8) + SALT (16) + IV (12) + CIPHERTEXT
    const magicBytes = encoder.encode(SECURITY_CONFIG.MAGIC_HEADER);
    const fileNameBytes = encoder.encode(nameToEncode);

    const packetSize = magicBytes.length + 2 + fileNameBytes.length + salt.length + iv.length + ciphertext.byteLength;
    const packet = new Uint8Array(packetSize);

    let offset = 0;

    // Magic Bytes
    packet.set(magicBytes, offset);
    offset += magicBytes.length;

    // Filename length (Uint16 Big-Endian)
    const dv = new DataView(packet.buffer);
    dv.setUint16(offset, fileNameBytes.length, false);
    offset += 2;

    // Filename bytes
    packet.set(fileNameBytes, offset);
    offset += fileNameBytes.length;

    // Salt
    packet.set(salt, offset);
    offset += salt.length;

    // IV
    packet.set(iv, offset);
    offset += iv.length;

    // Ciphertext
    packet.set(new Uint8Array(ciphertext), offset);

    return packet.buffer;
}
