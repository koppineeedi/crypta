/**
 * Context-Aware Actionable Security Recommendations Engine
 */

export function generateRecommendations(password, patternAnalysis, scoringResult) {
    const userAdvice = [];
    const devAdvice = [];

    // General Baseline Advice
    userAdvice.push('Use a unique password or passphrase for every online account.');
    userAdvice.push('Store your passwords securely in a trusted, open-source or audited password manager.');
    userAdvice.push('Enable Multi-Factor Authentication (MFA/2FA) on all critical accounts.');

    devAdvice.push('Never store plaintext passwords in databases or logs.');
    devAdvice.push('Use modern memory-hard password hashing algorithms (e.g. Argon2id, bcrypt, or PBKDF2 with >=100,000 iterations).');
    devAdvice.push('Enforce strict rate-limiting and account lockout throttling to defeat online brute-force attempts.');
    devAdvice.push('Implement k-anonymity breach checking during registration to block known compromised passwords.');

    // Context-Specific User Recommendations
    const len = password ? password.length : 0;
    if (len < 14) {
        userAdvice.unshift('Increase password length to at least 14–16 characters or use a 4+ word passphrase.');
    }

    for (const finding of patternAnalysis.findings) {
        switch (finding.type) {
            case 'COMMON_PASSWORD':
                userAdvice.unshift('CRITICAL: Replace this password immediately; it is listed in common breach datasets.');
                break;
            case 'DICTIONARY_WORD':
                userAdvice.push('Avoid standalone dictionary words. Combine multiple unrelated words into a passphrase.');
                break;
            case 'KEYBOARD_PATTERN':
                userAdvice.push('Avoid keyboard row sequences like "qwerty" or "12345"; automated crackers search these first.');
                break;
            case 'PREDICTABLE_SUBSTITUTION':
                userAdvice.push('Simple symbol substitutions (like "@" for "a") do not fool modern crackers. Focus on length.');
                break;
            case 'PREDICTABLE_TRANSFORMATION':
                userAdvice.push('Avoid ending passwords with predictable numbers or years (e.g. "2025!" or "123").');
                break;
            default:
                break;
        }
    }

    return {
        userAdvice: Array.from(new Set(userAdvice)),
        devAdvice: Array.from(new Set(devAdvice))
    };
}
