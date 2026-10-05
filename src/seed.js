const bcrypt = require('bcrypt');
const db = require('./config/db');
const env = require('./config/env');

const TEST_USERS = [
  { name: 'Sara SuperAdmin', email: 'superadmin@gateway.dev', password: 'SuperAdmin@123', role: 'SuperAdmin', tenant: 'Acme Corp' },
  { name: 'Mohsin Manager',  email: 'manager@gateway.dev',    password: 'Manager@123',    role: 'Manager',    tenant: 'Acme Corp' },
  { name: 'Ali Employee',    email: 'employee@gateway.dev',   password: 'Employee@123',   role: 'Employee',   tenant: 'Acme Corp' },
  { name: 'Hina Employee',   email: 'employee2@gateway.dev',  password: 'Employee@123',   role: 'Employee',   tenant: 'Acme Corp' },
  { name: 'Lockout Demo',    email: 'lockme@gateway.dev',     password: 'Employee@123',   role: 'Employee',   tenant: 'Acme Corp' },
  { name: 'Gul Globex Mgr',  email: 'manager@globex.dev',     password: 'Manager@123',    role: 'Manager',    tenant: 'Globex Inc' },
];

function seed({ quiet = false } = {}) {
  let created = 0;
  for (const u of TEST_USERS) {
    db.prepare('INSERT OR IGNORE INTO tenants (name) VALUES (?)').run(u.tenant);
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(u.email)) continue;
    const tenantId = db.prepare('SELECT id FROM tenants WHERE name = ?').get(u.tenant).id;
    db.prepare(`INSERT INTO users (tenant_id, name, email, password_hash, role, provider) VALUES (?, ?, ?, ?, ?, 'local')`)
      .run(tenantId, u.name, u.email, bcrypt.hashSync(u.password, env.BCRYPT_ROUNDS), u.role);
    created++;
  }
  if (!quiet) console.log(`Seed complete: ${created} user(s) created.`);
}

if (require.main === module) seed();
module.exports = { seed, TEST_USERS };
