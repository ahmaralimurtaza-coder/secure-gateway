const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../config/db');
const env = require('../config/env');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimit');
const { authenticate } = require('../middleware/auth');
const { schemas, validate } = require('../utils/validate');
const tokens = require('../utils/tokens');

const router = express.Router();
const DEFAULT_TENANT = 'Acme Corp';
// Used when the email doesn't exist, so response time doesn't reveal which emails are registered.
const DUMMY_HASH = bcrypt.hashSync('timing-attack-dummy', env.BCRYPT_ROUNDS);

const audit = (userId, action, detail, ip) =>
  db.prepare('INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)').run(userId, action, detail, ip);

function getOrCreateTenant(name = DEFAULT_TENANT) {
  db.prepare('INSERT OR IGNORE INTO tenants (name) VALUES (?)').run(name);
  return db.prepare('SELECT id FROM tenants WHERE name = ?').get(name).id;
}

const publicUser = (u) => ({
  id: u.id, name: u.name, email: u.email, role: u.role, tenantId: u.tenant_id,
  provider: u.provider, avatarUrl: u.avatar_url || null,
});

function startSession(res, user) {
  const { token } = tokens.issueRefreshToken(user.id);
  tokens.setRefreshCookie(res, token);
  return tokens.signAccessToken(user);
}

// ───────────────────────── Local auth ─────────────────────────

router.post('/register', registerLimiter, validate('body', schemas.register), async (req, res) => {
  const { name, email, password, tenant } = req.body;
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) {
    return res.status(409).json({ error: 'Conflict', message: 'Email already registered' });
  }
  const passwordHash = await bcrypt.hash(password, env.BCRYPT_ROUNDS); // salted automatically
  const tenantId = getOrCreateTenant(tenant);
  // Self-registration is ALWAYS 'Employee' — role cannot be chosen by the client (no privilege escalation).
  const { lastInsertRowid } = db.prepare(
    `INSERT INTO users (tenant_id, name, email, password_hash, role, provider) VALUES (?, ?, ?, ?, 'Employee', 'local')`
  ).run(tenantId, name, email, passwordHash);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(lastInsertRowid);
  audit(user.id, 'REGISTER', email, req.ip);
  const accessToken = startSession(res, user);
  res.status(201).json({ message: 'Registered successfully', accessToken, tokenType: 'Bearer', expiresIn: 900, user: publicUser(user) });
});

router.post('/login', loginLimiter, validate('body', schemas.login), async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  // Account lockout (DB-level, survives restarts of the rate limiter)
  if (user?.lock_until && user.lock_until > Date.now()) {
    const mins = Math.ceil((user.lock_until - Date.now()) / 60000);
    return res.status(423).json({ error: 'Locked', message: `Account locked after too many failed attempts. Try again in ${mins} minute(s).` });
  }

  const ok = await bcrypt.compare(password, user?.password_hash || DUMMY_HASH);
  if (!user || !user.password_hash || !ok) {
    if (user) {
      const attempts = (user.lock_until && user.lock_until <= Date.now()) ? 1 : user.failed_attempts + 1;
      const lockUntil = attempts >= env.LOGIN_MAX_ATTEMPTS ? Date.now() + env.LOGIN_WINDOW_MS : null;
      db.prepare('UPDATE users SET failed_attempts = ?, lock_until = ? WHERE id = ?').run(attempts, lockUntil, user.id);
      audit(user.id, lockUntil ? 'ACCOUNT_LOCKED' : 'LOGIN_FAILED', email, req.ip);
    }
    return res.status(401).json({ error: 'Unauthorized', message: 'Invalid email or password' });
  }

  db.prepare('UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = ?').run(user.id);
  audit(user.id, 'LOGIN', 'local', req.ip);
  const accessToken = startSession(res, user);
  res.json({ message: 'Login successful', accessToken, tokenType: 'Bearer', expiresIn: 900, user: publicUser(user) });
});

// ───────────────────────── Token rotation ─────────────────────────

router.post('/refresh', (req, res) => {
  const old = req.cookies?.[tokens.REFRESH_COOKIE];
  if (!old) return res.status(401).json({ error: 'Unauthorized', message: 'No refresh token cookie' });

  const result = tokens.rotateRefreshToken(old);
  if (result.error) {
    tokens.clearRefreshCookie(res);
    if (result.reuse) audit(result.userId, 'REFRESH_REUSE_DETECTED', 'family revoked', req.ip);
    return res.status(401).json({ error: 'Unauthorized', message: result.error });
  }
  tokens.setRefreshCookie(res, result.refreshToken);
  res.json({ message: 'Token rotated', accessToken: result.accessToken, tokenType: 'Bearer', expiresIn: 900, user: publicUser(result.user) });
});

router.post('/logout', (req, res) => {
  const refresh = req.cookies?.[tokens.REFRESH_COOKIE];
  if (refresh) tokens.revokeRefreshFamily(refresh);

  const [scheme, bearer] = (req.headers.authorization || '').split(' ');
  if (scheme === 'Bearer' && bearer) {
    try { tokens.revokeAccessToken(tokens.verifyAccessToken(bearer)); } catch { /* already invalid */ }
  }
  tokens.clearRefreshCookie(res);
  res.json({ message: 'Logged out. Refresh token and access token revoked.' });
});

router.get('/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: publicUser(user) });
});

// ───────────────────────── GitHub OAuth 2.0 ─────────────────────────

const STATE_COOKIE = 'oauth_state';
const callbackUrl = () => `${env.APP_URL}/api/v1/auth/github/callback`;

router.get('/github', (req, res) => {
  if (!env.GITHUB_CLIENT_ID) return res.status(503).json({ error: 'GitHub OAuth not configured' });
  const state = crypto.randomBytes(24).toString('hex');   // CSRF protection for the OAuth flow
  // SameSite=Lax (not Strict) because GitHub redirects back cross-site and we must read it there.
  res.cookie(STATE_COOKIE, state, { httpOnly: true, secure: true, sameSite: 'lax', path: '/api/v1/auth/github', maxAge: 10 * 60 * 1000 });
  const url = new URL('https://github.com/login/oauth/authorize');
  url.search = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID, redirect_uri: callbackUrl(), scope: 'read:user user:email', state,
  }).toString();
  res.redirect(url.toString());
});

router.get('/github/callback', async (req, res) => {
  const fail = (msg) => res.redirect(`/?error=${encodeURIComponent(msg)}`);
  const { code, state } = req.query;
  const expected = req.cookies?.[STATE_COOKIE];
  res.clearCookie(STATE_COOKIE, { path: '/api/v1/auth/github' });

  if (!code || !state || !expected || state.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(state), Buffer.from(expected))) {
    return fail('OAuth state mismatch');
  }

  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri: callbackUrl() }),
    });
    const { access_token: ghToken } = await tokenRes.json();
    if (!ghToken) return fail('GitHub token exchange failed');

    const gh = (path) => fetch(`https://api.github.com${path}`, {
      headers: { Authorization: `Bearer ${ghToken}`, Accept: 'application/vnd.github+json', 'User-Agent': 'secure-gateway' },
    }).then((r) => r.json());
    const [profile, emails] = await Promise.all([gh('/user'), gh('/user/emails')]);
    const primary = Array.isArray(emails) && emails.find((e) => e.primary && e.verified);
    if (!profile?.id || !primary) return fail('GitHub account needs a verified primary email');

    const email = primary.email.toLowerCase();
    const providerId = String(profile.id);
    const name = String(profile.name || profile.login).slice(0, 80);

    // Profile sync: match by GitHub id -> else link to an existing account with the same verified email -> else create.
    let user = db.prepare(`SELECT * FROM users WHERE provider = 'github' AND provider_id = ?`).get(providerId)
            || db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (user) {
      db.prepare(`UPDATE users SET name = ?, avatar_url = ?, provider = CASE WHEN password_hash IS NULL THEN 'github' ELSE 'local+github' END,
                  provider_id = ? WHERE id = ?`).run(name, profile.avatar_url, providerId, user.id);
    } else {
      const { lastInsertRowid } = db.prepare(
        `INSERT INTO users (tenant_id, name, email, role, provider, provider_id, avatar_url) VALUES (?, ?, ?, 'Employee', 'github', ?, ?)`
      ).run(getOrCreateTenant(), name, email, providerId, profile.avatar_url);
      user = { id: lastInsertRowid };
    }
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    audit(user.id, 'LOGIN', 'github', req.ip);

    // Issue OUR credentials: refresh token in httpOnly cookie. The SPA then calls /refresh to get an access token,
    // so no token ever appears in the URL.
    const { token } = tokens.issueRefreshToken(user.id);
    tokens.setRefreshCookie(res, token);
    res.redirect('/dashboard.html');
  } catch (err) {
    console.error('OAuth error:', err.message);
    fail('OAuth login failed');
  }
});

module.exports = router;
