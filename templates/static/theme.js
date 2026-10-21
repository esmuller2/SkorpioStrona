(function () {
    const html = document.documentElement;
    const saved = localStorage.getItem('theme') || 'light';
    html.setAttribute('data-theme', saved);

    function bindToggle() {
        const toggle = document.getElementById('themeToggle');
        if (!toggle || toggle.dataset.bound) return;
        toggle.dataset.bound = '1';
        toggle.textContent = saved === 'dark' ? '☀️' : '🌙';
        toggle.addEventListener('click', () => {
            const current = html.getAttribute('data-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', next);
            localStorage.setItem('theme', next);
            toggle.textContent = next === 'dark' ? '☀️' : '🌙';
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
