/**
 * Crypta Password Security Analyzer UI Controller
 */

import { analyzePassword } from '../password/analyzer.js';
import { checkPasswordBreach } from '../password/breachCheck.js';
import { escapeHtml } from '../utils/formatting.js';

export function initPasswordUI() {
    const pwdInput = document.getElementById('analyzer-password-input');
    const toggleBtn = document.getElementById('analyzer-toggle-password');

    const scoreNumber = document.getElementById('analyzer-score-number');
    const scoreRating = document.getElementById('analyzer-score-rating');
    const scoreFill = document.getElementById('analyzer-score-fill');

    const propLength = document.getElementById('prop-length');
    const propUpper = document.getElementById('prop-upper');
    const propLower = document.getElementById('prop-lower');
    const propDigit = document.getElementById('prop-digit');
    const propSymbol = document.getElementById('prop-symbol');
    const propRepeated = document.getElementById('prop-repeated');
    const propDict = document.getElementById('prop-dict');
    const propPattern = document.getElementById('prop-pattern');

    const attackOnline = document.getElementById('attack-online-val');
    const attackOnlineTime = document.getElementById('attack-online-time');
    const attackFast = document.getElementById('attack-fast-val');
    const attackFastTime = document.getElementById('attack-fast-time');
    const attackSlow = document.getElementById('attack-slow-val');
    const attackSlowTime = document.getElementById('attack-slow-time');

    const breachBtn = document.getElementById('btn-run-breach-check');
    const breachResult = document.getElementById('breach-result-area');

    const weaknessesList = document.getElementById('analyzer-weaknesses-list');
    const strengthsList = document.getElementById('analyzer-strengths-list');
    const recommendationsList = document.getElementById('analyzer-recommendations-list');
    const devAdviceList = document.getElementById('analyzer-dev-advice-list');

    // Toggle Password Visibility
    if (toggleBtn && pwdInput) {
        toggleBtn.addEventListener('click', () => {
            const type = pwdInput.getAttribute('type') === 'password' ? 'text' : 'password';
            pwdInput.setAttribute('type', type);
            const eyeOpen = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-icon"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
            const eyeClosed = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-icon"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" x2="23" y1="1" y2="23"/></svg>`;
            toggleBtn.innerHTML = type === 'password' ? eyeOpen : eyeClosed;
        });
    }

    function renderAnalysis() {
        const password = pwdInput ? pwdInput.value : '';
        const analysis = analyzePassword(password);

        // Score Meter
        if (scoreNumber) scoreNumber.textContent = analysis.score;
        if (scoreRating) {
            scoreRating.textContent = analysis.rating.toUpperCase();
            scoreRating.className = `badge badge-${getRatingBadgeClass(analysis.rating)}`;
        }
        if (scoreFill) {
            scoreFill.style.width = `${analysis.score}%`;
            scoreFill.style.backgroundColor = getScoreColor(analysis.score);
        }

        // Properties
        if (propLength) propLength.textContent = `${analysis.length} characters`;
        if (propUpper) propUpper.innerHTML = analysis.hasUpper ? '<span class="text-success">✓ Present</span>' : '<span class="text-muted">✗ Missing</span>';
        if (propLower) propLower.innerHTML = analysis.hasLower ? '<span class="text-success">✓ Present</span>' : '<span class="text-muted">✗ Missing</span>';
        if (propDigit) propDigit.innerHTML = analysis.hasDigit ? '<span class="text-success">✓ Present</span>' : '<span class="text-muted">✗ Missing</span>';
        if (propSymbol) propSymbol.innerHTML = analysis.hasSymbol ? '<span class="text-success">✓ Present</span>' : '<span class="text-muted">✗ Missing</span>';

        const hasRepeats = analysis.patterns.findings.some(f => f.type === 'REPEATED_CHARS' || f.type === 'REPEATED_SUBSTRING');
        if (propRepeated) propRepeated.innerHTML = hasRepeats ? '<span class="text-warning">⚠ Detected</span>' : '<span class="text-success">None</span>';

        const hasDict = analysis.patterns.findings.some(f => f.type === 'DICTIONARY_WORD' || f.type === 'COMMON_PASSWORD');
        if (propDict) propDict.innerHTML = hasDict ? '<span class="text-danger">⚠ Match Found</span>' : '<span class="text-success">None</span>';

        const hasPattern = analysis.patterns.findings.some(f => f.type === 'KEYBOARD_PATTERN' || f.type === 'SEQUENTIAL_CHARS' || f.type === 'PREDICTABLE_TRANSFORMATION');
        if (propPattern) propPattern.innerHTML = hasPattern ? '<span class="text-warning">⚠ High</span>' : '<span class="text-success">Low</span>';

        // Attack Resistance
        const ar = analysis.attackResistance;
        if (attackOnline) attackOnline.innerHTML = `<span class="badge badge-${getRatingBadgeClass(ar.onlineThrottled.rating)}">${ar.onlineThrottled.rating}</span>`;
        if (attackOnlineTime) attackOnlineTime.textContent = ar.onlineThrottled.timeEstimate;

        if (attackFast) attackFast.innerHTML = `<span class="badge badge-${getRatingBadgeClass(ar.offlineFastHash.rating)}">${ar.offlineFastHash.rating}</span>`;
        if (attackFastTime) attackFastTime.textContent = ar.offlineFastHash.timeEstimate;

        if (attackSlow) attackSlow.innerHTML = `<span class="badge badge-${getRatingBadgeClass(ar.offlineSlowHash.rating)}">${ar.offlineSlowHash.rating}</span>`;
        if (attackSlowTime) attackSlowTime.textContent = ar.offlineSlowHash.timeEstimate;

        // Weaknesses
        if (weaknessesList) {
            if (analysis.weaknesses.length === 0) {
                weaknessesList.innerHTML = '<li class="text-success">✓ No major weaknesses detected.</li>';
            } else {
                weaknessesList.innerHTML = analysis.weaknesses.map(w => `<li class="text-warning">⚠ ${escapeHtml(w)}</li>`).join('');
            }
        }

        // Strengths
        if (strengthsList) {
            strengthsList.innerHTML = analysis.strengths.map(s => `<li class="text-success">+ ${escapeHtml(s)}</li>`).join('');
        }

        // Suggestions
        if (recommendationsList) {
            recommendationsList.innerHTML = analysis.suggestions.map(rec => `<li>• ${escapeHtml(rec)}</li>`).join('');
        }

        if (devAdviceList) {
            devAdviceList.innerHTML = analysis.devAdvice.map(rec => `<li>🔒 ${escapeHtml(rec)}</li>`).join('');
        }

        // Reset breach result on password edit
        if (breachResult) {
            breachResult.innerHTML = '<p class="text-muted">Click below to check this password against known data breaches securely via k-Anonymity.</p>';
        }
    }

    if (pwdInput) {
        pwdInput.addEventListener('input', renderAnalysis);
    }

    // Breach Exposure Check Button Handler
    if (breachBtn) {
        breachBtn.addEventListener('click', async () => {
            const password = pwdInput ? pwdInput.value : '';
            if (!password) {
                if (breachResult) breachResult.innerHTML = '<p class="text-warning">Please enter a password to analyze breach exposure.</p>';
                return;
            }

            breachBtn.disabled = true;
            if (breachResult) breachResult.innerHTML = '<div class="loader-spinner"></div> <span class="text-muted">Searching breach database via local k-anonymity SHA-1 prefix...</span>';

            const res = await checkPasswordBreach(password);
            breachBtn.disabled = false;

            if (!breachResult) return;

            if (res.status === 'FOUND') {
                breachResult.innerHTML = `
                    <div class="alert alert-danger">
                        <strong>${escapeHtml(res.message)}</strong>
                        <p class="small text-muted mt-1">${escapeHtml(res.privacyNote)}</p>
                    </div>
                `;
            } else if (res.status === 'NOT_FOUND') {
                breachResult.innerHTML = `
                    <div class="alert alert-success">
                        <strong>${escapeHtml(res.message)}</strong>
                        <p class="small text-muted mt-1">${escapeHtml(res.privacyNote)}</p>
                    </div>
                `;
            } else {
                breachResult.innerHTML = `
                    <div class="alert alert-warning">
                        <strong>Breach check unavailable</strong>
                        <p>${escapeHtml(res.message)}</p>
                        <p class="small text-muted mt-1">${escapeHtml(res.privacyNote)}</p>
                    </div>
                `;
            }
        });
    }

    // Initial render
    renderAnalysis();
}

function getRatingBadgeClass(rating) {
    const r = String(rating).toUpperCase();
    if (r.includes('VERY HIGH') || r.includes('VERY STRONG')) return 'success';
    if (r.includes('HIGH') || r.includes('STRONG')) return 'info';
    if (r.includes('MODERATE')) return 'warning';
    return 'danger';
}

function getScoreColor(score) {
    if (score >= 85) return '#10b981'; // Emerald
    if (score >= 70) return '#06b6d4'; // Cyan
    if (score >= 50) return '#f59e0b'; // Amber
    if (score >= 30) return '#f97316'; // Orange
    return '#ef4444'; // Red
}
