(() => {
    const dashboard = document.querySelector(".dashboard-welcome");
    if (!dashboard) return;

    const customizeButton = dashboard.querySelector("#dashboard-customize");
    const preferences = dashboard.querySelector("#dashboard-preferences");
    const resetButton = dashboard.querySelector("#dashboard-reset");
    const status = dashboard.querySelector("#dashboard-preference-status");
    const toggles = [...dashboard.querySelectorAll("[data-widget-toggle]")];
    const storageKey = `cloud-rdx-admin-dashboard:${dashboard.dataset.dashboardUser || "default"}`;

    const showWidget = (name, visible) => {
        const widget = document.querySelector(`[data-dashboard-widget="${name}"]`);
        if (widget) widget.hidden = !visible;
    };

    const savePreferences = () => {
        const values = Object.fromEntries(
            toggles.map((toggle) => [toggle.dataset.widgetToggle, toggle.checked])
        );
        try {
            localStorage.setItem(storageKey, JSON.stringify(values));
            status.textContent = "Preferences saved in this browser.";
        } catch (error) {
            status.textContent = "This browser could not save dashboard preferences.";
        }
    };

    try {
        const saved = JSON.parse(localStorage.getItem(storageKey) || "{}");
        for (const toggle of toggles) {
            const value = saved[toggle.dataset.widgetToggle];
            if (typeof value === "boolean") toggle.checked = value;
            showWidget(toggle.dataset.widgetToggle, toggle.checked);
        }
    } catch (error) {
        status.textContent = "Dashboard preferences are unavailable in this browser.";
    }

    customizeButton.addEventListener("click", () => {
        const open = customizeButton.getAttribute("aria-expanded") !== "true";
        customizeButton.setAttribute("aria-expanded", String(open));
        preferences.hidden = !open;
        if (open) toggles[0]?.focus();
    });

    for (const toggle of toggles) {
        toggle.addEventListener("change", () => {
            showWidget(toggle.dataset.widgetToggle, toggle.checked);
            savePreferences();
        });
    }

    resetButton.addEventListener("click", () => {
        for (const toggle of toggles) {
            toggle.checked = true;
            showWidget(toggle.dataset.widgetToggle, true);
        }
        try {
            localStorage.removeItem(storageKey);
            status.textContent = "Dashboard restored to its default layout.";
        } catch (error) {
            status.textContent = "This browser could not reset dashboard preferences.";
        }
    });
})();

