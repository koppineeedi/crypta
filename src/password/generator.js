/**
 * Cryptographically Secure Password Generator
 * Uses Web Crypto API getRandomValues() exclusively for non-deterministic randomness.
 */

const UPPERCASE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const UPPERCASE_AMBIGUOUS = 'I O';
const UPPERCASE_ALL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

const LOWERCASE_CHARS = 'abcdefghijkmnopqrstuvwxyz';
const LOWERCASE_AMBIGUOUS = 'l i o';
const LOWERCASE_ALL = 'abcdefghijklmnopqrstuvwxyz';

const DIGIT_CHARS = '23456789';
const DIGIT_AMBIGUOUS = '0 1';
const DIGIT_ALL = '0123456789';

const SYMBOL_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?';

function getCrypto() {
    if (typeof window !== 'undefined' && window.crypto) {
        return window.crypto;
    }
    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
        return globalThis.crypto;
    }
    throw new Error('Web Crypto API is not supported in this environment.');
}

export function generateSecurePassword(options = {}) {
    const {
        length = 16,
        includeUppercase = true,
        includeLowercase = true,
        includeNumbers = true,
        includeSymbols = true,
        avoidAmbiguous = true
    } = options;

    if (length < 4 || length > 128) {
        throw new Error('Password length must be between 4 and 128 characters.');
    }

    let upperSet = avoidAmbiguous ? UPPERCASE_CHARS : UPPERCASE_ALL;
    let lowerSet = avoidAmbiguous ? LOWERCASE_CHARS : LOWERCASE_ALL;
    let digitSet = avoidAmbiguous ? DIGIT_CHARS : DIGIT_ALL;
    let symbolSet = SYMBOL_CHARS;

    const selectedPools = [];
    if (includeUppercase) selectedPools.push(upperSet);
    if (includeLowercase) selectedPools.push(lowerSet);
    if (includeNumbers) selectedPools.push(digitSet);
    if (includeSymbols) selectedPools.push(symbolSet);

    if (selectedPools.length === 0) {
        throw new Error('At least one character set must be selected.');
    }

    const fullPool = selectedPools.join('');
    const cryptoObj = getCrypto();
    const resultChars = [];

    // 1. Guarantee at least one character from each selected pool
    for (const pool of selectedPools) {
        const randIndex = getSecureRandomInt(cryptoObj, pool.length);
        resultChars.push(pool[randIndex]);
    }

    // 2. Fill remaining length from full combined pool
    while (resultChars.length < length) {
        const randIndex = getSecureRandomInt(cryptoObj, fullPool.length);
        resultChars.push(fullPool[randIndex]);
    }

    // 3. Shuffle result using Fisher-Yates with crypto randomness
    shuffleArraySecurely(resultChars, cryptoObj);

    return resultChars.join('');
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

function shuffleArraySecurely(array, cryptoObj) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = getSecureRandomInt(cryptoObj, i + 1);
        const temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}
