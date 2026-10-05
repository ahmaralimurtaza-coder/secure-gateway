const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const env = require('../config/env');

const json = (message) => (req, res, _next, options) =>
  res.status(options.statusCode).json({
    error: 'Too Many Requests',
    message,
    retryAfterSeconds: Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000),
  });

/** Max 5 FAILED login attempts per 15 minutes per IP + email. Successful logins don't count. */
const loginLimiter = rateLimit({
  windowMs: env.LOGIN_WINDOW_MS,
  limit: env.LOGIN_MAX_ATTEMPTS,
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => `${ipKeyGenerator(req.ip)}|${String(req.body?.email || '').toLowerCase()}`,
  handler: json('Too many failed login attempts. Try again in 15 minutes.'),
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false,
  handler: json('Too many accounts created from this IP. Try again later.'),
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false,
  handler: json('Too many requests. Slow down.'),
});

module.exports = { loginLimiter, registerLimiter, apiLimiter };
