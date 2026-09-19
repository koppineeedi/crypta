/**
 * Consolidated Password Security Analysis Engine API
 */

import { detectPatterns } from './patterns.js';
import { calculateScore } from './scoring.js';
import { estimateGuessability } from './guessability.js';
import { calculateAttackResistance } from './attackModels.js';
import { generateRecommendations } from './recommendations.js';

export function analyzePassword(password) {
    // 1. Detect structural patterns & diversity
    const patternAnalysis = detectPatterns(password || '');

    // 2. Compute explainable score & rating
    const scoringResult = calculateScore(password || '', patternAnalysis);

    // 3. Estimate entropy & guesses
    const guessability = estimateGuessability(password || '', patternAnalysis);

    // 4. Calculate multi-scenario attack resistance
    const attackResistance = calculateAttackResistance(guessability);

    // 5. Generate contextual advice
    const recommendations = generateRecommendations(password || '', patternAnalysis, scoringResult);

    return {
        score: scoringResult.score,
        rating: scoringResult.rating,
        label: scoringResult.label,
        entropyEstimate: guessability.entropyBits,
        estimatedGuesses: guessability.formattedGuesses,
        rawGuesses: guessability.estimatedGuesses,
        resistanceLevel: guessability.resistanceLevel,
        attackResistance: attackResistance,
        weaknesses: scoringResult.weaknesses,
        strengths: scoringResult.strengths,
        suggestions: recommendations.userAdvice,
        devAdvice: recommendations.devAdvice,
        patterns: patternAnalysis,
        length: (password || '').length,
        hasUpper: patternAnalysis.hasUpper,
        hasLower: patternAnalysis.hasLower,
        hasDigit: patternAnalysis.hasDigit,
        hasSymbol: patternAnalysis.hasSymbol
    };
}
