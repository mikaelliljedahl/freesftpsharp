// Color mode for Bootstrap 5.3 (data-bs-theme). The choice is kept in localStorage; "auto" follows the OS.
(function () {
    const storageKey = 'fxsftp-theme';
    const stored = () => { try { return localStorage.getItem(storageKey); } catch { return null; } };
    const effective = (mode) => mode === 'auto' || !mode
        ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
        : mode;
    const apply = (mode) => document.documentElement.setAttribute('data-bs-theme', effective(mode));

    apply(stored());
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => apply(stored()));

    window.fxTheme = {
        current: () => document.documentElement.getAttribute('data-bs-theme'),
        toggle: function () {
            const next = this.current() === 'dark' ? 'light' : 'dark';
            try { localStorage.setItem(storageKey, next); } catch { }
            apply(next);
            return next;
        }
    };
})();
