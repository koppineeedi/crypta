/**
 * Password Pattern Analysis Engine
 * Detects structural weaknesses, sequences, keyboard patterns, dictionary matches, leet speak, etc.
 */

const COMMON_PASSWORDS = new Set([
    'password', 'password123', 'password1', '123456', '12345678', '123456789', '1234567890',
    'qwerty', 'qwerty123', 'admin', 'admin123', 'administrator', 'letmein', 'welcome',
    'welcome1', 'welcome123', 'welcome2024', 'welcome2025', 'iloveyou', 'sunshine', 'princess',
    'football', 'monkey', 'charlie', 'donald', 'master', 'shadow', 'superman', 'michael',
    'p@ssw0rd', 'p@ssword', 'pass1234', 'pass@123', 'abc12345', '111111', '000000', '666666'
]);

const DICTIONARY_WORDS = new Set([
    'admin', 'password', 'welcome', 'login', 'security', 'system', 'account', 'access',
    'master', 'secret', 'shadow', 'dragon', 'knight', 'hunter', 'football', 'baseball',
    'sunshine', 'princess', 'freedom', 'flower', 'summer', 'winter', 'autumn', 'spring',
    'monkey', 'charlie', 'jordan', 'daniel', 'hannah', 'jessica', 'michael', 'andrew',
    'london', 'tokyo', 'paris', 'berlin', 'america', 'canada', 'russia', 'china', 'india',
    'google', 'microsoft', 'apple', 'facebook', 'twitter', 'github', 'amazon', 'netflix'
]);

const KEYBOARD_PATTERNS = [
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
    '1234567890', 'poiuytrewq', 'lkjhgfdsa', 'mnbvcxz',
    'qazwsxedc', 'rfvtgbyhn', 'ujmikolp',
    '!@#$%^&*()'
];

const LEET_MAP = {
    '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i',
    '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't',
    '8': 'b', '9': 'g'
};

export function detectPatterns(password) {
    const findings = [];
    const lowerPwd = password.toLowerCase();

    // 1. Length Checks
    const length = password.length;
    let isShort = false;
    if (length < 8) {
        findings.push({ type: 'SHORT_CRITICAL', message: 'Password is critically short (under 8 characters).' });
        isShort = true;
    } else if (length < 12) {
        findings.push({ type: 'SHORT_WARNING', message: 'Password is short (under 12 characters).' });
        isShort = true;
    }

    // 2. Character Diversity
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);

    const diversityCount = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;
    if (diversityCount < 3) {
        findings.push({ type: 'LOW_DIVERSITY', message: 'Password lacks character diversity (mix upper, lower, numbers, and symbols).' });
    }

    // 3. Repeated Characters (e.g. 'aaaaa' or '1111')
    if (/(.)\1{2,}/.test(password)) {
        findings.push({ type: 'REPEATED_CHARS', message: 'Repeated character sequences detected (e.g., "aaa" or "111").' });
    }

    // 4. Repeated Substrings (e.g. 'abcabc' or 'passpass')
    if (/(.{2,})\1+/.test(lowerPwd)) {
        findings.push({ type: 'REPEATED_SUBSTRING', message: 'Repeated word or pattern components detected.' });
    }

    // 5-7. Sequential Characters & Numeric/Alphabetic Sequences
    if (hasSequence(lowerPwd, 3)) {
        findings.push({ type: 'SEQUENTIAL_CHARS', message: 'Sequential character sequence detected (e.g., "123", "abc", or "zyx").' });
    }

    // 8. Keyboard Walks ('qwerty', 'asdfgh', etc.)
    for (const pattern of KEYBOARD_PATTERNS) {
        for (let i = 0; i <= pattern.length - 4; i++) {
            const sub = pattern.substring(i, i + 4);
            const rev = sub.split('').reverse().join('');
            if (lowerPwd.includes(sub) || lowerPwd.includes(rev)) {
                findings.push({ type: 'KEYBOARD_PATTERN', message: `Keyboard row pattern detected ("${sub}").` });
                break;
            }
        }
    }

    // 9 & 10. Common Password / Dictionary Match
    if (COMMON_PASSWORDS.has(lowerPwd)) {
        findings.push({ type: 'COMMON_PASSWORD', message: 'Contains an extremely common, blacklisted password.' });
    }

    // Demask Leet substitutions
    let demasked = lowerPwd;
    for (const [leet, original] of Object.entries(LEET_MAP)) {
        demasked = demasked.split(leet).join(original);
    }

    let dictionaryMatched = false;
    for (const word of DICTIONARY_WORDS) {
        if (lowerPwd.includes(word) || demasked.includes(word)) {
            dictionaryMatched = true;
            findings.push({ type: 'DICTIONARY_WORD', message: `Contains common dictionary term or name ("${word}").` });
            break;
        }
    }

    // 11. Common Substitutions (Leet Speak)
    if (demasked !== lowerPwd && dictionaryMatched) {
        findings.push({ type: 'PREDICTABLE_SUBSTITUTION', message: 'Predictable character substitutions detected (e.g., "@" for "a", "0" for "o").' });
    }

    // 12 & 13. Years and Dates
    const yearMatch = password.match(/(19\d\d|20[0-2]\d|2030)/);
    if (yearMatch) {
        findings.push({ type: 'YEAR_DETECTED', message: `Contains a recognizable year ("${yearMatch[0]}").` });
    }

    const dateMatch = password.match(/\b(0[1-9]|1[0-2])[-/.]?(0[1-9]|[12]\d|3[01])[-/.]?(19\d\d|20\d\d)\b/);
    if (dateMatch) {
        findings.push({ type: 'DATE_DETECTED', message: 'Contains a recognizable date pattern.' });
    }

    // 15. Excessive Predictable Symbols
    if (/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]{3,}/.test(password)) {
        findings.push({ type: 'EXCESSIVE_SYMBOLS', message: 'Consecutive symbol blocks detected (e.g. "!!!").' });
    }

    // 16 & 19. Prefix / Suffix Patterns (e.g. 'Password123!', 'Welcome2025!')
    if (/^[A-Z][a-z]+(123|2024|2025|1|!)?$/.test(password) || /[a-zA-Z]+(123|1234|!|2025)$/.test(password)) {
        findings.push({ type: 'PREDICTABLE_TRANSFORMATION', message: 'Predictable capitalized word with numeric/symbol suffix detected.' });
    }

    return {
        hasUpper,
        hasLower,
        hasDigit,
        hasSymbol,
        diversityCount,
        isShort,
        findings
    };
}

function hasSequence(str, minLength = 3) {
    for (let i = 0; i <= str.length - minLength; i++) {
        let asciiAsc = true;
        let asciiDesc = true;
        for (let j = 0; j < minLength - 1; j++) {
            const code1 = str.charCodeAt(i + j);
            const code2 = str.charCodeAt(i + j + 1);

            // Ignore non-alphanumeric for sequence testing
            if (!isAlphaNumericCode(code1) || !isAlphaNumericCode(code2)) {
                asciiAsc = false;
                asciiDesc = false;
                break;
            }

            if (code2 !== code1 + 1) asciiAsc = false;
            if (code2 !== code1 - 1) asciiDesc = false;
        }
        if (asciiAsc || asciiDesc) return true;
    }
    return false;
}

function isAlphaNumericCode(code) {
    return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}
