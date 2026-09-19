/**
 * Crypta Privacy & Security Center UI Controller
 */

export function initPrivacyUI() {
    const accordions = document.querySelectorAll('.accordion-header');

    accordions.forEach(header => {
        header.addEventListener('click', () => {
            const item = header.parentElement;
            const content = item.querySelector('.accordion-content');

            const isOpen = item.classList.contains('active');

            // Close all items
            document.querySelectorAll('.accordion-item').forEach(el => {
                el.classList.remove('active');
                const c = el.querySelector('.accordion-content');
                if (c) c.style.display = 'none';
            });

            if (!isOpen && content) {
                item.classList.add('active');
                content.style.display = 'block';
            }
        });
    });
}
