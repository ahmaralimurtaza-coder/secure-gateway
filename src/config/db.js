const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { DB_PATH } = require('./env');

if (DB_PATH !== ':memory:') fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// All queries in this project use prepared statements (parameter binding) -> SQL injection safe.
db.exec(`
CREATE TABLE IF NOT EXISTS tenants (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL UNIQUE,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id        INTEGER NOT NULL REFERENCES tenants(id),
  name             TEXT NOT NULL,
  email            TEXT NOT NULL UNIQUE,
  password_hash    TEXT,                       -- NULL for pure OAuth accounts
  role             TEXT NOT NULL DEFAULT 'Employee'
                   CHECK (role IN ('SuperAdmin','Manager','Employee')),
  provider         TEXT NOT NULL DEFAULT 'local',
  provider_id      TEXT,
  avatar_url       TEXT,
  failed_attempts  INTEGER NOT NULL DEFAULT 0,
  lock_until       INTEGER,                    -- epoch ms
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (provider, provider_id)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id           TEXT PRIMARY KEY,               -- jti
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id    TEXT NOT NULL,                  -- rotation chain
  token_hash   TEXT NOT NULL,                  -- sha256 of the token, never the raw token
  expires_at   INTEGER NOT NULL,
  revoked      INTEGER NOT NULL DEFAULT 0,
  replaced_by  TEXT,
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_access_tokens (
  jti         TEXT PRIMARY KEY,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS payroll_approvals (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id    INTEGER NOT NULL REFERENCES tenants(id),
  employee_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  month        TEXT NOT NULL,
  amount       REAL NOT NULL,
  approved_by  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  approved_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER,
  action     TEXT NOT NULL,
  detail     TEXT,
  ip         TEXT,
  at         TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

module.exports = db;
