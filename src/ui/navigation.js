/**
 * Crypta UI Module Navigation & Router Controller
 */

export function initNavigation() {
    const navLinks = document.querySelectorAll('[data-target-module]');
    const moduleSections = document.querySelectorAll('.module-section');

    function switchModule(targetId) {
        // Update active nav link states
        navLinks.forEach(link => {
            if (link.getAttribute('data-target-module') === targetId) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });

        // Toggle module visibility
        moduleSections.forEach(section => {
            if (section.id === targetId) {
                section.classList.remove('hidden');
                section.classList.add('active');
            } else {
                section.classList.add('hidden');
                section.classList.remove('active');
            }
        });

        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('data-target-module');
            if (targetId) {
                switchModule(targetId);
            }
        });
    });

    return { switchModule };
}
