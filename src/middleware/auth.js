const db = require('../config/db');
const { verifyAccessToken } = require('../utils/tokens');

/** Verifies `Authorization: Bearer <accessToken>` */
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Missing Bearer access token' });
  }
  try {
    const payload = verifyAccessToken(token);
    const user = db.prepare('SELECT id, tenant_id, name, email, role FROM users WHERE id = ?').get(Number(payload.sub));
    if (!user) return res.status(401).json({ error: 'Unauthorized', message: 'User no longer exists' });
    req.user = user;          // role is read from DB, so a role change takes effect immediately
    req.tokenPayload = payload;
    next();
  } catch (err) {
    const expired = err.name === 'TokenExpiredError';
    return res.status(401).json({
      error: 'Unauthorized',
      message: expired ? 'Access token expired. Call /api/v1/auth/refresh' : 'Invalid or revoked access token',
    });
  }
}

/** RBAC: checkRole(['SuperAdmin', 'Manager']) */
function checkRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!allowedRoles.includes(req.user.role)) {
      db.prepare('INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
        .run(req.user.id, 'RBAC_DENIED', `${req.method} ${req.originalUrl}`, req.ip);
      return res.status(403).json({
        error: 'Forbidden',
        message: `Role '${req.user.role}' is not allowed. Required: ${allowedRoles.join(' or ')}`,
      });
    }
    next();
  };
}

module.exports = { authenticate, checkRole };
