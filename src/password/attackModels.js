/**
 * Multi-Scenario Attack Resistance Model Engine
 * Evaluates online rate-limited, offline fast hash, and offline slow hash resistance.
 */

import { SECURITY_CONFIG } from '../crypto/securityConfig.js';
import { formatTimeEstimate } from '../utils/formatting.js';

export function calculateAttackResistance(guessability) {
    const totalGuesses = guessability.estimatedGuesses || 1;

    // Rates (guesses/sec)
    const onlineRate = SECURITY_CONFIG.ATTACK_MODELS.ONLINE_THROTTLED;
    const fastHashRate = SECURITY_CONFIG.ATTACK_MODELS.OFFLINE_FAST_HASH;
    const slowHashRate = SECURITY_CONFIG.ATTACK_MODELS.OFFLINE_SLOW_HASH;

    // Average guesses needed to find password (50% of search space)
    const avgGuesses = totalGuesses / 2;

    const onlineSeconds = avgGuesses / onlineRate;
    const fastHashSeconds = avgGuesses / fastHashRate;
    const slowHashSeconds = avgGuesses / slowHashRate;

    return {
        onlineThrottled: {
            name: 'Online Throttled Attack',
            rate: '~100 attempts / min',
            timeEstimate: formatTimeEstimate(onlineSeconds),
            rating: getScenarioRating(onlineSeconds, 86400, 31536000), // 1 day, 1 year
            description: 'Protects against direct website login rate-limiting controls.'
        },
        offlineFastHash: {
            name: 'Offline Fast-Hash Attack',
            rate: '~10^10 hashes / sec',
            timeEstimate: formatTimeEstimate(fastHashSeconds),
            rating: getScenarioRating(fastHashSeconds, 3600, 86400 * 30), // 1 hour, 30 days
            description: 'Simulates high-end GPU clusters targeting fast unsalted hashes (MD5 / SHA-1).'
        },
        offlineSlowHash: {
            name: 'Offline Slow Password-Hash Attack',
            rate: '~10,000 hashes / sec',
            timeEstimate: formatTimeEstimate(slowHashSeconds),
            rating: getScenarioRating(slowHashSeconds, 86400 * 7, 31536000 * 5), // 7 days, 5 years
            description: 'Simulates offline cracking against modern password key derivation (Argon2 / PBKDF2 100k).'
        },
        estimationExplanation: `
How is this estimated?
Crypta calculates password guessability using a structural pattern-deduction model.
- Online Throttled assumes server-side login rate limits (~100 attempts/min).
- Offline Fast Hash assumes a multi-GPU cracking cluster computing 10 billion fast hashes per second.
- Offline Slow Hash assumes a hardened server using PBKDF2 or Argon2 (~10,000 hashes per second).
This is a defensive model for evaluation purposes and does not guarantee invulnerability.
        `.trim()
    };
}

function getScenarioRating(seconds, moderateThreshold, highThreshold) {
    if (seconds >= highThreshold) return 'VERY HIGH';
    if (seconds >= moderateThreshold) return 'HIGH';
    if (seconds >= 300) return 'MODERATE';
    return 'LOW';
}
