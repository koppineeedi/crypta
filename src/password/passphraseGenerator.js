/**
 * Secure Diceware Passphrase Generator
 * Generates memorable high-entropy passphrases using EFF wordlist & Web Crypto API.
 */

import { EFF_WORDLIST } from '../utils/diceware.js';

function getCrypto() {
    if (typeof window !== 'undefined' && window.crypto) {
        return window.crypto;
    }
    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
        return globalThis.crypto;
    }
    throw new Error('Web Crypto API is not supported in this environment.');
}

export function generatePassphrase(options = {}) {
    const {
        wordCount = 4,
        separator = '-',
        includeNumber = false,
        includeSymbol = false
    } = options;

    if (wordCount < 3 || wordCount > 10) {
        throw new Error('Word count must be between 3 and 10 words.');
    }

    const cryptoObj = getCrypto();
    const chosenWords = [];

    // Select random words using cryptographically secure indices
    for (let i = 0; i < wordCount; i++) {
        const randIndex = getSecureRandomInt(cryptoObj, EFF_WORDLIST.length);
        chosenWords.push(EFF_WORDLIST[randIndex]);
    }

    // Optionally append number or symbol to one of the words
    if (includeNumber) {
        const numIndex = getSecureRandomInt(cryptoObj, chosenWords.length);
        const randDigit = getSecureRandomInt(cryptoObj, 10);
        chosenWords[numIndex] += randDigit.toString();
    }

    if (includeSymbol) {
        const symbols = '!@#$%^&*';
        const symWordIndex = getSecureRandomInt(cryptoObj, chosenWords.length);
        const randSymIndex = getSecureRandomInt(cryptoObj, symbols.length);
        chosenWords[symWordIndex] += symbols[randSymIndex];
    }

    return chosenWords.join(separator);
}

function getSecureRandomInt(cryptoObj, maxExclusive) {
    if (maxExclusive <= 0) return 0;
    const randomBuffer = new Uint32Array(1);
    const maxUint32 = 0xFFFFFFFF;
    const limit = maxUint32 - (maxUint32 % maxExclusive);

    let rand;
    do {
        cryptoObj.getRandomValues(randomBuffer);
        rand = randomBuffer[0];
    } while (rand >= limit);

    return rand % maxExclusive;
}
