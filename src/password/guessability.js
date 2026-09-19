/**
 * Guessability & Entropy Estimation Engine
 * Calculates estimated guess resistance and log10 guess counts.
 */

import { formatScientificGuesses } from '../utils/formatting.js';

export function estimateGuessability(password, patternAnalysis) {
    if (!password) {
        return {
            entropyBits: 0,
            estimatedGuesses: 1,
            formattedGuesses: '1',
            resistanceLevel: 'Low',
            disclaimer: "Model-based estimate. Actual attack resistance depends on the attacker's hardware, password hashing algorithm, available dictionaries, leaks, and attack strategy."
        };
    }

    // 1. Calculate pool size based on character diversity
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^A-Za-z0-9]/.test(password)) poolSize += 33;

    if (poolSize === 0) poolSize = 1;

    // 2. Base Shannon Entropy = len * log2(poolSize)
    let rawEntropy = password.length * Math.log2(poolSize);

    // Apply deductions for structural patterns (repeats, dictionary words, keyboard walks)
    let deductionFactor = 1.0;
    for (const finding of patternAnalysis.findings) {
        if (finding.type === 'COMMON_PASSWORD') deductionFactor *= 0.1;
        if (finding.type === 'DICTIONARY_WORD') deductionFactor *= 0.4;
        if (finding.type === 'KEYBOARD_PATTERN') deductionFactor *= 0.5;
        if (finding.type === 'SEQUENTIAL_CHARS') deductionFactor *= 0.6;
        if (finding.type === 'REPEATED_CHARS') deductionFactor *= 0.7;
        if (finding.type === 'PREDICTABLE_TRANSFORMATION') deductionFactor *= 0.6;
    }

    const effectiveEntropyBits = Math.max(1, Math.round(rawEntropy * deductionFactor));

    // Estimated guesses = 2^(effectiveEntropyBits - 1)
    const estimatedGuesses = Math.pow(2, effectiveEntropyBits);

    // Categorize resistance level
    let resistanceLevel = 'Low';
    if (effectiveEntropyBits >= 85) {
        resistanceLevel = 'Very High';
    } else if (effectiveEntropyBits >= 60) {
        resistanceLevel = 'High';
    } else if (effectiveEntropyBits >= 40) {
        resistanceLevel = 'Moderate';
    }

    return {
        entropyBits: effectiveEntropyBits,
        estimatedGuesses: estimatedGuesses,
        formattedGuesses: formatScientificGuesses(estimatedGuesses),
        resistanceLevel,
        disclaimer: "Model-based estimate. Actual attack resistance depends on the attacker's hardware, password hashing algorithm, available dictionaries, leaks, and attack strategy."
    };
}
