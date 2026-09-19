/**
 * Explainable Password Security Scoring Engine
 * Computes a 0–100 Crypta Security Estimate with itemized strengths & weaknesses.
 */

export function calculateScore(password, patternAnalysis) {
    if (!password) {
        return {
            score: 0,
            rating: 'Critical',
            label: 'Crypta Security Estimate',
            strengths: [],
            weaknesses: ['Password is empty.']
        };
    }

    let score = 0;
    const strengths = [];
    const weaknesses = [];

    const len = password.length;

    // 1. Length scoring (Passphrases & long passwords benefit exponentially from length)
    if (len >= 30) {
        score += 70;
        strengths.push('Exceptional length (30+ characters / passphrase)');
    } else if (len >= 24) {
        score += 55;
        strengths.push('Extremely strong length (24–29 characters)');
    } else if (len >= 18) {
        score += 42;
        strengths.push('Strong length (18–23 characters)');
    } else if (len >= 14) {
        score += 30;
        strengths.push('Good length (14–17 characters)');
    } else if (len >= 12) {
        score += 20;
        strengths.push('Moderate length (12–13 characters)');
    } else if (len >= 8) {
        score += 10;
        weaknesses.push('Short password length (under 12 characters)');
    } else {
        score += 2;
        weaknesses.push('Critically short length (under 8 characters)');
    }

    // 2. Character diversity
    const { hasUpper, hasLower, hasDigit, hasSymbol, diversityCount } = patternAnalysis;
    if (diversityCount === 4) {
        score += 25;
        strengths.push('Complete character diversity (uppercase, lowercase, numbers, symbols)');
    } else if (diversityCount === 3) {
        score += 18;
        strengths.push('Good character diversity (3 character sets used)');
    } else if (diversityCount === 2) {
        score += 10;
        if (len < 20) {
            weaknesses.push('Limited character diversity (only 2 character sets used)');
        } else {
            strengths.push('Passphrase format with word separators');
        }
    } else {
        score += 3;
        if (len < 20) {
            weaknesses.push('Very low character diversity (only 1 character set used)');
        }
    }

    // Individual character set bonuses
    if (hasUpper && hasLower) score += 5;
    if (hasSymbol) score += 5;
    if (hasDigit) score += 5;

    // Uniqueness ratio bonus
    const uniqueChars = new Set(password).size;
    const uniqueRatio = uniqueChars / len;
    if (uniqueRatio > 0.6 && len >= 12) {
        score += 10;
        strengths.push('High character uniqueness');
    }

    // 3. Penalties based on pattern findings
    for (const finding of patternAnalysis.findings) {
        switch (finding.type) {
            case 'COMMON_PASSWORD':
                score -= 40;
                weaknesses.push('Matches a blacklisted, commonly breached password');
                break;
            case 'DICTIONARY_WORD':
                // Only penalize single dictionary words in short passwords (< 20 chars), not multi-word passphrases
                if (len < 20) {
                    score -= 20;
                    weaknesses.push('Contains a standalone common dictionary word or name');
                }
                break;
            case 'KEYBOARD_PATTERN':
                score -= 15;
                weaknesses.push('Contains keyboard row patterns (e.g. "qwerty")');
                break;
            case 'SEQUENTIAL_CHARS':
                score -= 15;
                weaknesses.push('Contains sequential letters or numbers (e.g. "123", "abc")');
                break;
            case 'REPEATED_CHARS':
                score -= 10;
                weaknesses.push('Contains repeated character sequences');
                break;
            case 'PREDICTABLE_SUBSTITUTION':
                score -= 10;
                weaknesses.push('Uses predictable leet substitutions (e.g. "@" for "a")');
                break;
            case 'YEAR_DETECTED':
                score -= 8;
                weaknesses.push('Includes a recognizable calendar year');
                break;
            case 'PREDICTABLE_TRANSFORMATION':
                score -= 15;
                weaknesses.push('Uses predictable capitalization or suffix patterns');
                break;
            default:
                break;
        }
    }

    // Clamp score to 0 - 100 range
    score = Math.max(0, Math.min(100, Math.round(score)));

    // Rating Categories
    let rating = 'Critical';
    if (score >= 85) {
        rating = 'Very Strong';
    } else if (score >= 70) {
        rating = 'Strong';
    } else if (score >= 50) {
        rating = 'Moderate';
    } else if (score >= 30) {
        rating = 'Weak';
    }

    if (strengths.length === 0) {
        strengths.push('Basic character input provided');
    }

    return {
        score,
        rating,
        label: 'Crypta Security Estimate',
        strengths,
        weaknesses
    };
}
