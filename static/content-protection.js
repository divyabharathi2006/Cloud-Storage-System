(() => {
    'use strict';

    // Client-side deterrent only. It cannot protect content from developer tools,
    // browser extensions, screenshots, or users who disable JavaScript.
    const isEditable = (target) => target instanceof Element && Boolean(
        target.closest('input, textarea, select, button, [contenteditable="true"], [role="textbox"]')
    );

    document.addEventListener('contextmenu', (event) => {
        if (!isEditable(event.target)) event.preventDefault();
    });

    document.addEventListener('copy', (event) => {
        if (!isEditable(event.target)) event.preventDefault();
    });

    document.addEventListener('cut', (event) => {
        if (!isEditable(event.target)) event.preventDefault();
    });

    document.addEventListener('dragstart', (event) => {
        if (!isEditable(event.target)) event.preventDefault();
    });

    document.addEventListener('keydown', (event) => {
        if (isEditable(event.target)) return;
        const key = event.key.toLowerCase();
        if ((event.ctrlKey || event.metaKey) && ['c', 'x'].includes(key)) {
            event.preventDefault();
        }
    });
})();

