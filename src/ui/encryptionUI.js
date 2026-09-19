/**
 * Crypta File Security UI Controller (Encrypt / Decrypt)
 */

import { encryptFile } from '../crypto/encryption.js';
import { decryptFile } from '../crypto/decryption.js';
import { analyzePassword } from '../password/analyzer.js';
import { formatBytes } from '../utils/formatting.js';

export function initEncryptionUI() {
    const btnEncrypt = document.getElementById('btn-encrypt');
    const btnDecrypt = document.getElementById('btn-decrypt');
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const filePrompt = document.querySelector('.dropzone-prompt');
    const fileInfo = document.getElementById('file-info');
    const infoName = document.getElementById('info-name');
    const infoSize = document.getElementById('info-size');
    const btnRemoveFile = document.getElementById('btn-remove-file');

    const cryptoForm = document.getElementById('crypto-form');
    const passwordInput = document.getElementById('password-input');
    const togglePasswordBtn = document.getElementById('toggle-password');
    const strengthMeter = document.getElementById('strength-meter');
    const strengthFill = document.getElementById('strength-fill');
    const strengthText = document.getElementById('strength-text');
    const actionSubmit = document.getElementById('action-submit');
    const submitText = document.getElementById('submit-text');

    const statusSection = document.getElementById('status-section');
    const statusMessage = document.getElementById('status-message');
    const progressFill = document.getElementById('progress-fill');

    const downloadSection = document.getElementById('download-section');
    const resultTitle = document.getElementById('result-title');
    const resultDesc = document.getElementById('result-desc');
    const downloadLink = document.getElementById('download-link');
    const btnReset = document.getElementById('btn-reset');

    let currentMode = 'encrypt';
    let selectedFile = null;

    function setMode(mode) {
        currentMode = mode;
        if (mode === 'encrypt') {
            btnEncrypt.classList.add('active');
            btnDecrypt.classList.remove('active');
            submitText.textContent = 'Encrypt File';
            passwordInput.placeholder = 'Enter password to secure file';
            strengthMeter.classList.remove('hidden');
        } else {
            btnDecrypt.classList.add('active');
            btnEncrypt.classList.remove('active');
            submitText.textContent = 'Decrypt File';
            passwordInput.placeholder = 'Enter decryption password';
            strengthMeter.classList.add('hidden');
        }
        updateSubmitButtonState();
    }

    if (btnEncrypt) btnEncrypt.addEventListener('click', () => setMode('encrypt'));
    if (btnDecrypt) btnDecrypt.addEventListener('click', () => setMode('decrypt'));

    // Password visibility toggle
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', () => {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);

            const eyeOpen = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-icon"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
            const eyeClosed = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-icon"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" x2="23" y1="1" y2="23"/></svg>`;

            togglePasswordBtn.innerHTML = type === 'password' ? eyeOpen : eyeClosed;
        });
    }

    // Password Strength Meter
    if (passwordInput) {
        passwordInput.addEventListener('input', () => {
            const password = passwordInput.value;
            if (!password || currentMode === 'decrypt') {
                strengthMeter.classList.add('hidden');
                updateSubmitButtonState();
                return;
            }

            strengthMeter.classList.remove('hidden');
            const analysis = analyzePassword(password);
            
            let width = `${analysis.score}%`;
            let color = '#ef4444'; // Red

            if (analysis.score >= 70) {
                color = '#10b981'; // Green
            } else if (analysis.score >= 50) {
                color = '#f59e0b'; // Amber
            }

            strengthFill.style.width = width;
            strengthFill.style.backgroundColor = color;
            strengthText.textContent = `Password Strength: ${analysis.rating} (${analysis.score}/100)`;

            updateSubmitButtonState();
        });
    }

    // File Drag & Drop
    function handleFile(file) {
        if (!file) return;
        selectedFile = file;
        infoName.textContent = file.name;
        infoSize.textContent = formatBytes(file.size);

        filePrompt.classList.add('hidden');
        fileInfo.classList.remove('hidden');
        updateSubmitButtonState();
    }

    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFile(e.target.files[0]);
            }
        });
    }

    if (dropzone) {
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('dragover');
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                handleFile(e.dataTransfer.files[0]);
            }
        });
    }

    if (btnRemoveFile) {
        btnRemoveFile.addEventListener('click', (e) => {
            e.stopPropagation();
            resetFileSelection();
        });
    }

    function resetFileSelection() {
        selectedFile = null;
        if (fileInput) fileInput.value = '';
        fileInfo.classList.add('hidden');
        filePrompt.classList.remove('hidden');
        updateSubmitButtonState();
    }

    function updateSubmitButtonState() {
        const hasFile = selectedFile !== null;
        const hasPassword = passwordInput.value.length > 0;
        if (actionSubmit) {
            actionSubmit.disabled = !(hasFile && hasPassword);
        }
    }

    // Form Submit
    if (cryptoForm) {
        cryptoForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!selectedFile || !passwordInput.value) return;

            cryptoForm.classList.add('hidden');
            statusSection.classList.remove('hidden');
            progressFill.style.width = '20%';

            try {
                if (currentMode === 'encrypt') {
                    statusMessage.textContent = 'Deriving encryption key via PBKDF2...';
                    await sleep(300);
                    progressFill.style.width = '50%';

                    statusMessage.textContent = 'Encrypting file with AES-256-GCM...';
                    const encryptedBuffer = await encryptFile(selectedFile, selectedFile.name, passwordInput.value);
                    progressFill.style.width = '85%';
                    await sleep(200);

                    statusMessage.textContent = 'Generating encrypted download file...';
                    const blob = new Blob([encryptedBuffer], { type: 'application/octet-stream' });
                    const downloadUrl = URL.createObjectURL(blob);

                    resultTitle.textContent = 'File Encrypted Successfully!';
                    resultDesc.textContent = 'Your file has been secured locally in your browser using AES-GCM 256-bit encryption.';
                    downloadLink.href = downloadUrl;
                    downloadLink.download = `${selectedFile.name}.enc`;
                } else {
                    statusMessage.textContent = 'Deriving key and verifying file header...';
                    await sleep(300);
                    progressFill.style.width = '50%';

                    statusMessage.textContent = 'Decrypting file payload...';
                    const result = await decryptFile(selectedFile, passwordInput.value);
                    progressFill.style.width = '85%';
                    await sleep(200);

                    statusMessage.textContent = 'Preparing restored file download...';
                    const blob = new Blob([result.decryptedBuffer], { type: 'application/octet-stream' });
                    const downloadUrl = URL.createObjectURL(blob);

                    resultTitle.textContent = 'File Decrypted Successfully!';
                    resultDesc.textContent = `Your file "${result.originalName}" was decrypted successfully and is ready to download.`;
                    downloadLink.href = downloadUrl;
                    downloadLink.download = result.originalName;
                }

                progressFill.style.width = '100%';
                await sleep(200);
                statusSection.classList.add('hidden');
                downloadSection.classList.remove('hidden');
            } catch (error) {
                alert(error.message || 'An error occurred during processing.');
                statusSection.classList.add('hidden');
                cryptoForm.classList.remove('hidden');
            }
        });
    }

    if (btnReset) {
        btnReset.addEventListener('click', () => {
            passwordInput.value = '';
            strengthMeter.classList.add('hidden');
            resetFileSelection();
            downloadSection.classList.add('hidden');
            cryptoForm.classList.remove('hidden');
        });
    }

    return { setMode };
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
