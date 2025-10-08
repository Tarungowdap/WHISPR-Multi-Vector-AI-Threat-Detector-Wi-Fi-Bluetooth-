document.addEventListener('DOMContentLoaded', () => {
    const body = document.body;
    const toggleButton = document.getElementById('theme-toggle');

    // 1. Load saved theme preference
    const savedTheme = localStorage.getItem('theme') || 'dark';

    // Apply the saved theme on page load
    const applyTheme = (theme) => {
        if (theme === 'light') {
            body.classList.add('light-mode');
            if (toggleButton) {
                toggleButton.textContent = 'Mode: Light';
            }
        } else {
            body.classList.remove('light-mode');
            if (toggleButton) {
                 toggleButton.textContent = 'Mode: Dark';
            }
        }
    };
    
    applyTheme(savedTheme);

    // 2. Add click listener to the toggle button
    if (toggleButton) {
        toggleButton.addEventListener('click', () => {
            if (body.classList.contains('light-mode')) {
                // Switch to dark mode
                applyTheme('dark');
                localStorage.setItem('theme', 'dark');
            } else {
                // Switch to light mode
                applyTheme('light');
                localStorage.setItem('theme', 'light');
            }
        });
    }
});
