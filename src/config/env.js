require('dotenv').config({ quiet: true });

const required = ['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET'];
for (const key of required) {
  if (!process.env[key]) {
    if (process.env.NODE_ENV === 'production') throw new Error(`Missing env var ${key}`);
    process.env[key] = `dev-only-${key}-change-me`;
  }
}

module.exports = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: Number(process.env.PORT) || 3000,
  APP_URL: (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, ''),
  CORS_ORIGINS: (process.env.CORS_ORIGINS || process.env.APP_URL || 'http://localhost:3000')
    .split(',').map((s) => s.trim().replace(/\/$/, '')).filter(Boolean),
  DB_PATH: process.env.DB_PATH || 'data/gateway.db',
  JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET,
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
  ACCESS_TTL: '15m',
  REFRESH_TTL_MS: 7 * 24 * 60 * 60 * 1000,
  BCRYPT_ROUNDS: 12,
  LOGIN_MAX_ATTEMPTS: 5,
  LOGIN_WINDOW_MS: 15 * 60 * 1000,
  GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID || '',
  GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET || '',
};
