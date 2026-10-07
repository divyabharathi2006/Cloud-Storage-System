(() => {
    const root = document.documentElement;
    const storageKey = "cloud-rdx-theme";
    let storageAvailable = true;

    try {
        const savedTheme = localStorage.getItem(storageKey);
        if (savedTheme === "dark" || savedTheme === "light") {
            root.dataset.theme = savedTheme;
        }
    } catch {
        storageAvailable = false;
    }

    document.addEventListener("DOMContentLoaded", () => {
        const toggle = document.getElementById("theme-toggle");
        const label = document.getElementById("theme-toggle-label");
        const status = document.getElementById("theme-status");
        if (!toggle || !label || !status) return;

        const applyTheme = (theme, announce = false) => {
            root.dataset.theme = theme;
            const isLight = theme === "light";
            label.textContent = isLight ? "Light theme" : "Dark theme";
            toggle.setAttribute("aria-pressed", String(isLight));
            toggle.setAttribute(
                "aria-label",
                `${isLight ? "Light" : "Dark"} theme selected. Activate to switch to ${isLight ? "dark" : "light"} theme.`
            );
            if (announce) {
                status.textContent = `${isLight ? "Light" : "Dark"} theme enabled.`;
            }
        };

        applyTheme(root.dataset.theme === "light" ? "light" : "dark");
        if (!storageAvailable) {
            status.textContent = "Theme preference could not be read; dark theme is active.";
        }

        toggle.addEventListener("click", () => {
            const nextTheme = root.dataset.theme === "light" ? "dark" : "light";
            applyTheme(nextTheme, true);
            try {
                localStorage.setItem(storageKey, nextTheme);
            } catch {
                status.textContent = "Theme changed for this visit, but this browser could not save the preference.";
            }
        });
    });
})();

