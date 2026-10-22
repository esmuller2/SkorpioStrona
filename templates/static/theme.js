(function () {
    const html = document.documentElement;
    const saved = localStorage.getItem('theme') || 'light';
    html.setAttribute('data-theme', saved);

    const moonIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 14.5A8.5 8.5 0 1 1 9.5 3 7 7 0 0 0 21 14.5z"/></svg>';
    const sunIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';

    function setToggleIcon(toggle, theme) {
        toggle.innerHTML = theme === 'dark' ? sunIcon : moonIcon;
        toggle.title = theme === 'dark' ? 'Tryb jasny' : 'Tryb ciemny';
    }

    function bindToggle() {
        const toggle = document.getElementById('themeToggle');
        if (!toggle || toggle.dataset.bound) return;
        toggle.dataset.bound = '1';
        setToggleIcon(toggle, saved);
        toggle.addEventListener('click', () => {
            const current = html.getAttribute('data-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', next);
            localStorage.setItem('theme', next);
            setToggleIcon(toggle, next);
        });
    }

    function bindLogout() {
        document.querySelectorAll('form[action="/logout"]').forEach(form => {
            if (form.dataset.bound) return;
            form.dataset.bound = '1';
            form.addEventListener('submit', () => {
                sessionStorage.removeItem('tab_auth');
            });
        });
    }

    const params = new URLSearchParams(window.location.search);
    if (params.get('tabauth') === '1') {
        sessionStorage.setItem('tab_auth', '1');
        params.delete('tabauth');
        const clean = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
        window.history.replaceState({}, '', clean);
    }

    const isLogin = window.location.pathname === '/login';
    if (!isLogin && !sessionStorage.getItem('tab_auth')) {
        window.location.replace('/login?reauth=1');
        return;
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            bindToggle();
            bindLogout();
        });
    } else {
        bindToggle();
        bindLogout();
    }
})();
