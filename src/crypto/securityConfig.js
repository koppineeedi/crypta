/**
 * Centralized Security Configuration for Crypta
 */

export const SECURITY_CONFIG = {
    // Encryption Constants
    KEY_ALGORITHM: 'AES-GCM',
    KEY_LENGTH: 256,             // 256-bit AES
    KDF_ALGORITHM: 'PBKDF2',
    KDF_ITERATIONS: 100000,       // 100,000 iterations
    SALT_LENGTH: 16,             // 16 bytes random salt
    IV_LENGTH: 12,               // 12 bytes random IV for AES-GCM
    HASH_ALGORITHM: 'SHA-256',

    // File Header Header Magic Bytes
    MAGIC_HEADER: 'CRYPTA',       // 6 ASCII bytes

    // HIBP Breach Checker API
    HIBP_API_URL: 'https://api.pwnedpasswords.com/range/',
    HIBP_PREFIX_LENGTH: 5,

    // Password Entropy & Guessability Constants
    ATTACK_MODELS: {
        ONLINE_THROTTLED: 100 / 60,          // 100 guesses / min = ~1.66 guesses/sec
        OFFLINE_FAST_HASH: 1e10,             // 10 Billion hashes / sec (MD5 / SHA-1 GPU cluster)
        OFFLINE_SLOW_HASH: 1e4,              // 10,000 hashes / sec (Argon2 / PBKDF2 100k)
    }
};
