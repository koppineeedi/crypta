/**
 * Crypta Password & Passphrase Generator UI Controller
 */

import { generateSecurePassword } from '../password/generator.js';
import { generatePassphrase } from '../password/passphraseGenerator.js';
import { analyzePassword } from '../password/analyzer.js';

export function initGeneratorUI() {
    // --- Password Generator Elements ---
    const pwdOutput = document.getElementById('gen-password-output');
    const pwdBtnGenerate = document.getElementById('btn-generate-password');
    const pwdBtnCopy = document.getElementById('btn-copy-password');
    const pwdLengthInput = document.getElementById('gen-length-slider');
    const pwdLengthVal = document.getElementById('gen-length-val');

    const chkUpper = document.getElementById('gen-chk-upper');
    const chkLower = document.getElementById('gen-chk-lower');
    const chkDigits = document.getElementById('gen-chk-digits');
    const chkSymbols = document.getElementById('gen-chk-symbols');
    const chkAmbiguous = document.getElementById('gen-chk-ambiguous');

    const pwdStrengthScore = document.getElementById('gen-pwd-strength-score');
    const pwdStrengthRating = document.getElementById('gen-pwd-strength-rating');

    // --- Passphrase Generator Elements ---
    const passOutput = document.getElementById('gen-passphrase-output');
    const passBtnGenerate = document.getElementById('btn-generate-passphrase');
    const passBtnCopy = document.getElementById('btn-copy-passphrase');
    const passWordsSelect = document.getElementById('gen-pass-words');
    const passSeparatorSelect = document.getElementById('gen-pass-separator');
    const passChkNumber = document.getElementById('gen-pass-chk-number');
    const passChkSymbol = document.getElementById('gen-pass-chk-symbol');

    const passStrengthScore = document.getElementById('gen-pass-strength-score');
    const passStrengthRating = document.getElementById('gen-pass-strength-rating');

    // --- Password Generator Logic ---
    function doGeneratePassword() {
        if (!pwdOutput) return;

        const length = parseInt(pwdLengthInput ? pwdLengthInput.value : 16, 10);
        const options = {
            length,
            includeUppercase: chkUpper ? chkUpper.checked : true,
            includeLowercase: chkLower ? chkLower.checked : true,
            includeNumbers: chkDigits ? chkDigits.checked : true,
            includeSymbols: chkSymbols ? chkSymbols.checked : true,
            avoidAmbiguous: chkAmbiguous ? chkAmbiguous.checked : true
        };

        try {
            const password = generateSecurePassword(options);
            pwdOutput.value = password;

            const analysis = analyzePassword(password);
            if (pwdStrengthScore) pwdStrengthScore.textContent = `${analysis.score}/100`;
            if (pwdStrengthRating) pwdStrengthRating.textContent = analysis.rating;
        } catch (e) {
            alert(e.message || 'Error generating password.');
        }
    }

    if (pwdLengthInput) {
        pwdLengthInput.addEventListener('input', () => {
            if (pwdLengthVal) pwdLengthVal.textContent = pwdLengthInput.value;
            doGeneratePassword();
        });
    }

    [chkUpper, chkLower, chkDigits, chkSymbols, chkAmbiguous].forEach(chk => {
        if (chk) chk.addEventListener('change', doGeneratePassword);
    });

    if (pwdBtnGenerate) pwdBtnGenerate.addEventListener('click', doGeneratePassword);

    if (pwdBtnCopy) {
        pwdBtnCopy.addEventListener('click', () => {
            if (pwdOutput && pwdOutput.value) {
                navigator.clipboard.writeText(pwdOutput.value).then(() => {
                    const origText = pwdBtnCopy.textContent;
                    pwdBtnCopy.textContent = 'Copied!';
                    setTimeout(() => { pwdBtnCopy.textContent = origText; }, 2000);
                });
            }
        });
    }

    // --- Passphrase Generator Logic ---
    function doGeneratePassphrase() {
        if (!passOutput) return;

        const wordCount = parseInt(passWordsSelect ? passWordsSelect.value : 4, 10);
        const separator = passSeparatorSelect ? passSeparatorSelect.value : '-';
        const options = {
            wordCount,
            separator,
            includeNumber: passChkNumber ? passChkNumber.checked : false,
            includeSymbol: passChkSymbol ? passChkSymbol.checked : false
        };

        try {
            const passphrase = generatePassphrase(options);
            passOutput.value = passphrase;

            const analysis = analyzePassword(passphrase);
            if (passStrengthScore) passStrengthScore.textContent = `${analysis.score}/100`;
            if (passStrengthRating) passStrengthRating.textContent = analysis.rating;
        } catch (e) {
            alert(e.message || 'Error generating passphrase.');
        }
    }

    if (passWordsSelect) passWordsSelect.addEventListener('change', doGeneratePassphrase);
    if (passSeparatorSelect) passSeparatorSelect.addEventListener('change', doGeneratePassphrase);
    if (passChkNumber) passChkNumber.addEventListener('change', doGeneratePassphrase);
    if (passChkSymbol) passChkSymbol.addEventListener('change', doGeneratePassphrase);

    if (passBtnGenerate) passBtnGenerate.addEventListener('click', doGeneratePassphrase);

    if (passBtnCopy) {
        passBtnCopy.addEventListener('click', () => {
            if (passOutput && passOutput.value) {
                navigator.clipboard.writeText(passOutput.value).then(() => {
                    const origText = passBtnCopy.textContent;
                    passBtnCopy.textContent = 'Copied!';
                    setTimeout(() => { passBtnCopy.textContent = origText; }, 2000);
                });
            }
        });
    }

    // Initial triggers
    doGeneratePassword();
    doGeneratePassphrase();
}
