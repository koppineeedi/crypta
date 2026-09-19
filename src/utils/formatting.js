/**
 * Formatting Utilities for Crypta Toolkit
 */

export function formatBytes(bytes, decimals = 2) {
    if (bytes === 0 || bytes === undefined || bytes === null) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

export function formatNumber(num) {
    if (num === null || num === undefined) return '0';
    return new Intl.NumberFormat().format(num);
}

export function formatScientificGuesses(guesses) {
    if (!guesses || guesses <= 0) return '1';
    if (guesses < 1000) return `${Math.round(guesses)}`;
    const log10 = Math.floor(Math.log10(guesses));
    return `~10^${log10}`;
}

export function formatTimeEstimate(seconds) {
    if (seconds === Infinity || seconds > 3.15e11) {
        return 'Centuries+';
    }
    if (seconds < 1) {
        return 'Instant';
    }
    if (seconds < 60) {
        return `${Math.round(seconds)} seconds`;
    }
    const minutes = seconds / 60;
    if (minutes < 60) {
        return `${Math.round(minutes)} minutes`;
    }
    const hours = minutes / 60;
    if (hours < 24) {
        return `${Math.round(hours)} hours`;
    }
    const days = hours / 24;
    if (days < 365) {
        return `${Math.round(days)} days`;
    }
    const years = days / 365;
    if (years < 100) {
        return `${Math.round(years)} years`;
    }
    return 'Centuries+';
}

export function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
