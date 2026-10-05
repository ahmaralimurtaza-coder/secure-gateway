const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const env = require('./config/env');
const { sanitize } = require('./middleware/sanitize');
const { apiLimiter } = require('./middleware/rateLimit');
const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');

const app = express();
app.set('trust proxy', 1); // behind Render/Railway proxy → correct client IP for rate limiting

// ── OWASP: secure HTTP headers ──
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'default-src': ["'self'"],
      'script-src': ["'self'"],
      'style-src': ["'self'", 'https://fonts.googleapis.com'],
      'font-src': ["'self'", 'https://fonts.gstatic.com'],
      'img-src': ["'self'", 'data:', 'https://avatars.githubusercontent.com'],
      'connect-src': ["'self'"],
      'form-action': ["'self'", 'https://github.com'],
      'frame-ancestors': ["'none'"],
    },
  },
  strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'no-referrer' },
}));

// ── OWASP: strict CORS (whitelist only, credentials allowed) ──
const corsMw = cors({
  origin(origin, cb) {
    if (!origin || env.CORS_ORIGINS.includes(origin)) return cb(null, true); // no Origin = same-origin / Postman / curl
    const err = new Error(`CORS: origin ${origin} not allowed`);
    err.status = 403;
    cb(err);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600,
});
app.use('/api', corsMw);

// ── Body parsing with size limits ──
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());

// ── OWASP: sanitize body / query / params (NoSQL operators, prototype pollution, XSS) ──
app.use(sanitize);

app.get('/health', (_req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

app.use('/api', apiLimiter);
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1', apiRoutes);

// Small frontend for the OAuth demo
app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html' }));

app.use('/api', (_req, res) => res.status(404).json({ error: 'Not Found' }));

// Central error handler — never leaks stack traces
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  if (status >= 500) console.error(err);
  const message = status >= 500 ? 'Internal Server Error'
    : err.type === 'entity.too.large' ? 'Payload too large'
    : err.type === 'entity.parse.failed' ? 'Malformed JSON' : err.message;
  res.status(status).json({ error: message });
});

module.exports = app;
