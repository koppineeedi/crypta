/**
 * Crypta Dashboard UI Controller
 */

export function initDashboard(navController, fileUIController) {
    const btnDashEncrypt = document.getElementById('dash-btn-encrypt');
    const btnDashDecrypt = document.getElementById('dash-btn-decrypt');
    const btnDashAnalyze = document.getElementById('dash-btn-analyze');

    if (btnDashEncrypt) {
        btnDashEncrypt.addEventListener('click', () => {
            navController.switchModule('file-module');
            if (fileUIController && fileUIController.setMode) {
                fileUIController.setMode('encrypt');
            }
        });
    }

    if (btnDashDecrypt) {
        btnDashDecrypt.addEventListener('click', () => {
            navController.switchModule('file-module');
            if (fileUIController && fileUIController.setMode) {
                fileUIController.setMode('decrypt');
            }
        });
    }

    if (btnDashAnalyze) {
        btnDashAnalyze.addEventListener('click', () => {
            navController.switchModule('password-analyzer-module');
        });
    }
}
