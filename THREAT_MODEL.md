# Threat Model — Crypta Client-Side Security Toolkit

## Overview
This document outlines the threat model for **Crypta**, a client-side file encryption and password security web application.

---

## 1. System Assets
- **User Files (Plaintext)**: Confidential user documents, images, archives, or binaries processed locally.
- **Encrypted Payload (.enc)**: Ciphertext formatted with Magic Bytes (`CRYPTA`), filename metadata, 16-byte random salt, 12-byte random IV, and AES-GCM 256-bit tag.
- **Master Passwords & Passphrases**: Secrets supplied by the user to derive cryptographic keys or analyze password security.
- **Generated Passwords/Passphrases**: High-entropy strings generated via Web Crypto API.

---

## 2. Threat Vectors & Attack Scenarios

### A. Network Eavesdropping & Server Compromise
- **Threat**: Interception of plaintext files or passwords in transit.
- **Mitigation**: 100% client-side execution via browser Web Crypto API (`window.crypto.subtle`). Files and plaintext passwords NEVER leave the browser or get sent to any server.

### B. Offline Brute-Force & Dictionary Attacks against Encrypted Files
- **Threat**: An attacker acquires an `.enc` file and attempts offline key cracking using fast GPUs.
- **Mitigation**: Crypta employs PBKDF2 key derivation with **100,000 iterations of SHA-256** and a **16-byte cryptographically random salt**. This forces significant computational overhead per guess attempt.

### C. Ciphertext Tampering & Bit-Flipping
- **Threat**: Modification of bytes within the `.enc` file to manipulate decrypted output.
- **Mitigation**: Crypta uses **AES-256-GCM** (Galois/Counter Mode), an authenticated encryption algorithm. Any modification to the ciphertext, IV, or header invalidates the 128-bit authentication tag and causes immediate decryption rejection.

### D. Password Breach Exposure Lookup Leakage
- **Threat**: Exposing plaintext passwords to third-party APIs during breach checking.
- **Mitigation**: Uses the **Have I Been Pwned k-Anonymity API**. Crypta computes a SHA-1 hash locally in the browser, sends ONLY the first 5 hex characters (`prefix`) over HTTPS, and performs the remaining 35-character suffix comparison locally inside the browser memory.

### E. Weak Randomness Exploits
- **Threat**: Predictable random numbers leading to key reuse or weak password generation.
- **Mitigation**: `Math.random()` is STRICTLY PROHIBITED. All salt, IV, and password generation calls use `crypto.getRandomValues()`.

---

## 3. Trust Boundaries & Environmental Limitations

### Browser Environment & Device Security
- **Compromised Host Machine**: If the user's host operating system or browser is infected with malware, keyloggers, or malicious browser extensions, client-side cryptographic guarantees CANNOT be preserved.
- **Memory Retention**: Passwords exist in browser memory during execution and are cleared when the tab is closed or variables fall out of scope. However, JavaScript memory management (garbage collection) does not guarantee immediate zeroization of memory blocks.

---

## 4. Security Controls Summary Matrix

| Asset | Threat | Security Control | Verification |
| :--- | :--- | :--- | :--- |
| **Files** | Server interception | Client-side Web Crypto execution | 0 network payloads |
| **Ciphertext** | Tampering / Bit flips | AES-256-GCM Authenticated Encryption | Tag verification test |
| **Encryption Keys** | Offline brute-force | PBKDF2 SHA-256 (100,000 iterations) | Unit test roundtrip |
| **Password Lookup** | Plaintext leak | k-Anonymity (5-char SHA-1 prefix) | Network inspector audit |
| **Randomness** | Predictability | `crypto.getRandomValues()` | Unit test uniqueness |
