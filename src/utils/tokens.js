const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const env = require('../config/env');

const sha256 = (v) => crypto.createHash('sha256').update(v).digest('hex');
const REFRESH_COOKIE = 'refresh_token';

const cookieOptions = {
  httpOnly: true,          // JS cannot read it (XSS-safe)
  secure: true,            // HTTPS only (localhost is treated as secure by browsers)
  sameSite: 'strict',      // never sent on cross-site requests (CSRF-safe)
  path: '/api/v1/auth',    // only sent to auth endpoints
  maxAge: env.REFRESH_TTL_MS,
};

function signAccessToken(user) {
  return jwt.sign(
    { sub: String(user.id), role: user.role, tid: user.tenant_id, email: user.email },
    env.JWT_ACCESS_SECRET,
    { expiresIn: env.ACCESS_TTL, jwtid: crypto.randomUUID(), algorithm: 'HS256' }
  );
}

function verifyAccessToken(token) {
  const payload = jwt.verify(token, env.JWT_ACCESS_SECRET, { algorithms: ['HS256'] });
  const revoked = db.prepare('SELECT 1 FROM revoked_access_tokens WHERE jti = ?').get(payload.jti);
  if (revoked) throw new Error('Token revoked');
  return payload;
}

function issueRefreshToken(userId, familyId = crypto.randomUUID()) {
  const jti = crypto.randomUUID();
  const token = jwt.sign({ sub: String(userId), fam: familyId }, env.JWT_REFRESH_SECRET, {
    expiresIn: Math.floor(env.REFRESH_TTL_MS / 1000), jwtid: jti, algorithm: 'HS256',
  });
  const now = Date.now();
  db.prepare(`INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at, created_at)
              VALUES (?, ?, ?, ?, ?, ?)`).run(jti, userId, familyId, sha256(token), now + env.REFRESH_TTL_MS, now);
  return { token, jti, familyId };
}

/**
 * Refresh Token Rotation with reuse detection.
 * - Valid token  -> revoke it, issue a new one in the same family.
 * - Reused token -> someone stole it: revoke the WHOLE family (force re-login).
 */
function rotateRefreshToken(oldToken) {
  let payload;
  try {
    payload = jwt.verify(oldToken, env.JWT_REFRESH_SECRET, { algorithms: ['HS256'] });
  } catch {
    return { error: 'Invalid or expired refresh token' };
  }
  const row = db.prepare('SELECT * FROM refresh_tokens WHERE id = ?').get(payload.jti);
  if (!row || row.token_hash !== sha256(oldToken)) return { error: 'Unknown refresh token' };

  if (row.revoked) {
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?').run(row.family_id);
    return { error: 'Refresh token reuse detected. All sessions in this chain revoked.', reuse: true, userId: row.user_id };
  }
  if (row.expires_at < Date.now()) return { error: 'Refresh token expired' };

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
  if (!user) return { error: 'User no longer exists' };

  const next = db.transaction(() => {
    const issued = issueRefreshToken(user.id, row.family_id);
    db.prepare('UPDATE refresh_tokens SET revoked = 1, replaced_by = ? WHERE id = ?').run(issued.jti, row.id);
    return issued;
  })();

  return { user, refreshToken: next.token, accessToken: signAccessToken(user) };
}

function revokeRefreshFamily(token) {
  try {
    const payload = jwt.verify(token, env.JWT_REFRESH_SECRET, { algorithms: ['HS256'], ignoreExpiration: true });
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?').run(payload.fam);
  } catch { /* ignore malformed token on logout */ }
}

function revokeAccessToken(payload) {
  db.prepare('INSERT OR IGNORE INTO revoked_access_tokens (jti, expires_at) VALUES (?, ?)')
    .run(payload.jti, payload.exp * 1000);
}

function cleanupExpired() {
  const now = Date.now();
  db.prepare('DELETE FROM revoked_access_tokens WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ?').run(now);
}

function setRefreshCookie(res, token) { res.cookie(REFRESH_COOKIE, token, cookieOptions); }
function clearRefreshCookie(res) {
  const { maxAge, ...opts } = cookieOptions;
  res.clearCookie(REFRESH_COOKIE, opts);
}

module.exports = {
  REFRESH_COOKIE, signAccessToken, verifyAccessToken, issueRefreshToken, rotateRefreshToken,
  revokeRefreshFamily, revokeAccessToken, cleanupExpired, setRefreshCookie, clearRefreshCookie,
};
