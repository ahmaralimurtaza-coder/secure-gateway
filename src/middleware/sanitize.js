const { filterXSS } = require('xss');

const xssOptions = { whiteList: {}, stripIgnoreTag: true, stripIgnoreTagBody: ['script', 'style'] };
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const SKIP_XSS = new Set(['password', 'currentPassword', 'newPassword']); // hashed, never rendered

/**
 * - NoSQL injection: drops keys starting with `$` or containing `.` (operator / path injection),
 *   plus prototype-pollution keys.
 * - XSS: strips HTML tags from every string value.
 * - SQL injection: handled at the DB layer — every query uses prepared statements.
 */
function clean(value, key) {
  if (typeof value === 'string') return SKIP_XSS.has(key) ? value : filterXSS(value, xssOptions).trim();
  if (Array.isArray(value)) return value.map((v) => clean(v, key));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (k.startsWith('$') || k.includes('.') || FORBIDDEN_KEYS.has(k)) continue;
      out[k] = clean(v, k);
    }
    return out;
  }
  return value;
}

function sanitize(req, _res, next) {
  if (req.body) req.body = clean(req.body);
  if (req.params) req.params = clean(req.params);
  if (req.query) {
    const q = clean(req.query);
    for (const k of Object.keys(req.query)) delete req.query[k];
    Object.assign(req.query, q);
  }
  next();
}

module.exports = { sanitize, clean };
