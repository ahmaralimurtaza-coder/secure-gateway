(() => {
  const $ = (id) => document.getElementById(id);
  let accessToken = null; // kept in memory only — never localStorage (XSS-safe)

  async function api(path, { method = 'GET', body, auth = true } = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth && accessToken) headers.Authorization = `Bearer ${accessToken}`;
    const res = await fetch(`/api/v1${path}`, {
      method, headers, credentials: 'same-origin', body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }

  const setMsg = (el, text, ok) => { el.textContent = text; el.className = `msg ${ok ? 'ok' : 'err'}`; };

  // ───────── Login page ─────────
  if ($('loginForm')) {
    const err = new URLSearchParams(location.search).get('error');
    if (err) setMsg($('loginMsg'), err, false);

    document.querySelectorAll('[data-e]').forEach((b) => b.addEventListener('click', () => {
      $('email').value = b.dataset.e; $('password').value = b.dataset.p;
    }));

    $('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const { status, data } = await api('/auth/login', {
        method: 'POST', auth: false, body: { email: $('email').value, password: $('password').value },
      });
      if (status === 200) location.href = '/dashboard.html';
      else setMsg($('loginMsg'), `${status}: ${data.message || data.error}`, false);
    });

    $('registerForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const { status, data } = await api('/auth/register', {
        method: 'POST', auth: false,
        body: { name: $('rname').value, email: $('remail').value, password: $('rpassword').value },
      });
      if (status === 201) location.href = '/dashboard.html';
      else setMsg($('registerMsg'), data.details ? data.details.map((d) => d.message).join(', ') : (data.message || data.error), false);
    });
  }

  // ───────── Dashboard ─────────
  if ($('refreshBtn')) {
    const show = (status, data) => {
      $('status').textContent = status;
      $('status').className = `status s${String(status)[0]}`;
      $('output').textContent = JSON.stringify(data, null, 2);
    };

    async function refresh() {
      const { status, data } = await api('/auth/refresh', { method: 'POST', auth: false });
      if (status !== 200) { location.href = `/?error=${encodeURIComponent('Session expired, please log in')}`; return null; }
      accessToken = data.accessToken;
      const u = data.user;
      $('userName').textContent = u.name;
      $('userEmail').textContent = `${u.email} · tenant #${u.tenantId} · via ${u.provider}`;
      $('userRole').textContent = u.role;
      $('userRole').className = `badge role-${u.role}`;
      if (u.avatarUrl) { $('avatar').src = u.avatarUrl; $('avatar').classList.remove('hidden'); }
      $('tokenView').textContent = `${accessToken.slice(0, 40)}…`;
      return { status, data };
    }

    refresh();
    $('refreshBtn').addEventListener('click', async () => { const r = await refresh(); if (r) show(r.status, r.data); });

    const calls = {
      profile: () => api('/employee/profile'),
      users: () => api('/users'),
      payroll: () => api('/payroll/approve', { method: 'POST', body: { employeeId: 3, month: new Date().toISOString().slice(0, 7), amount: 85000 } }),
      delete: () => {
        const id = prompt('User id to delete (try 4 = employee2):', '4');
        return id ? api(`/users/${encodeURIComponent(id)}`, { method: 'DELETE' }) : null;
      },
    };
    document.querySelectorAll('[data-call]').forEach((b) => b.addEventListener('click', async () => {
      const p = calls[b.dataset.call]();
      if (!p) return;
      const { status, data } = await p;
      show(status, data);
    }));

    $('logoutBtn').addEventListener('click', async () => {
      await api('/auth/logout', { method: 'POST' });
      accessToken = null;
      location.href = '/';
    });
  }
})();
