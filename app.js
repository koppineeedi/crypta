/**
 * Crypta — Client-Side Encryption & Password Security Toolkit
 * Main Application Orchestrator
 */

import { initNavigation } from './src/ui/navigation.js';
import { initDashboard } from './src/ui/dashboard.js';
import { initEncryptionUI } from './src/ui/encryptionUI.js';
import { initPasswordUI } from './src/ui/passwordUI.js';
import { initGeneratorUI } from './src/ui/generatorUI.js';
import { initReuseUI } from './src/ui/reuseUI.js';
import { initPrivacyUI } from './src/ui/privacyUI.js';

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Navigation Router
    const navController = initNavigation();

    // 2. Initialize Module Controllers
    const fileUIController = initEncryptionUI();
    initDashboard(navController, fileUIController);
    initPasswordUI();
    initGeneratorUI();
    initReuseUI();
    initPrivacyUI();
});
