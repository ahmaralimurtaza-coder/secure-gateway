process.env.DB_PATH = ':memory:';
process.env.NODE_ENV = 'test';

const { test, before } = require('node:test');
const assert = require('node:assert');
const request = require('supertest');
const app = require('../src/app');
const db = require('../src/config/db');
const { seed } = require('../src/seed');

const cookieOf = (res) => (res.headers['set-cookie'] || []).find((c) => c.startsWith('refresh_token='));
const login = (email, password) => request(app).post('/api/v1/auth/login').send({ email, password });
const tokens = {};

before(async () => {
  seed({ quiet: true });
  for (const [k, e, p] of [['sa', 'superadmin@gateway.dev', 'SuperAdmin@123'], ['mgr', 'manager@gateway.dev', 'Manager@123'], ['emp', 'employee@gateway.dev', 'Employee@123']]) {
    tokens[k] = (await login(e, p)).body.accessToken;
  }
});

test('passwords are bcrypt hashed, never plain text', () => {
  const row = db.prepare('SELECT password_hash FROM users WHERE email = ?').get('employee@gateway.dev');
  assert.match(row.password_hash, /^\$2[aby]\$12\$/);
  assert.notStrictEqual(row.password_hash, 'Employee@123');
});

test('register: weak password rejected, role cannot be injected', async () => {
  const weak = await request(app).post('/api/v1/auth/register').send({ name: 'X Y', email: 'x@y.dev', password: '123' });
  assert.strictEqual(weak.status, 400);
  const inject = await request(app).post('/api/v1/auth/register').send({ name: 'X Y', email: 'x@y.dev', password: 'Strong@123', role: 'SuperAdmin' });
  assert.strictEqual(inject.status, 400); // .strict() schema rejects unknown "role" field
  const ok = await request(app).post('/api/v1/auth/register').send({ name: 'New User', email: 'new@y.dev', password: 'Strong@123' });
  assert.strictEqual(ok.status, 201);
  assert.strictEqual(ok.body.user.role, 'Employee');
});

test('login sets httpOnly + Secure + SameSite=Strict refresh cookie', async () => {
  const res = await login('manager@gateway.dev', 'Manager@123');
  assert.strictEqual(res.status, 200);
  const c = cookieOf(res);
  assert.ok(c && /HttpOnly/i.test(c) && /Secure/i.test(c) && /SameSite=Strict/i.test(c), c);
  assert.ok(res.body.accessToken);
});

test('refresh token rotation + reuse detection', async () => {
  const res = await login('employee@gateway.dev', 'Employee@123');
  const c1 = cookieOf(res).split(';')[0];
  const r1 = await request(app).post('/api/v1/auth/refresh').set('Cookie', c1);
  assert.strictEqual(r1.status, 200);
  const c2 = cookieOf(r1).split(';')[0];
  assert.notStrictEqual(c1, c2, 'refresh token must change');
  // reuse old token → rejected and whole family revoked
  const reuse = await request(app).post('/api/v1/auth/refresh').set('Cookie', c1);
  assert.strictEqual(reuse.status, 401);
  assert.match(reuse.body.message, /reuse/i);
  const r2 = await request(app).post('/api/v1/auth/refresh').set('Cookie', c2);
  assert.strictEqual(r2.status, 401, 'newest token also revoked after reuse');
});

test('logout revokes refresh and access tokens', async () => {
  const res = await login('employee@gateway.dev', 'Employee@123');
  const c = cookieOf(res).split(';')[0];
  const at = res.body.accessToken;
  const out = await request(app).post('/api/v1/auth/logout').set('Cookie', c).set('Authorization', `Bearer ${at}`);
  assert.strictEqual(out.status, 200);
  assert.strictEqual((await request(app).post('/api/v1/auth/refresh').set('Cookie', c)).status, 401);
  assert.strictEqual((await request(app).get('/api/v1/employee/profile').set('Authorization', `Bearer ${at}`)).status, 401);
});

test('RBAC route matrix', async () => {
  const get = (t) => request(app).get('/api/v1/employee/profile').set('Authorization', `Bearer ${t}`);
  const pay = (t) => request(app).post('/api/v1/payroll/approve').set('Authorization', `Bearer ${t}`).send({ employeeId: 3, month: '2026-10', amount: 50000 });
  const del = (t, id) => request(app).delete(`/api/v1/users/${id}`).set('Authorization', `Bearer ${t}`);

  for (const t of [tokens.sa, tokens.mgr, tokens.emp]) assert.strictEqual((await get(t)).status, 200);
  assert.strictEqual((await get('bad')).status, 401);
  assert.strictEqual((await request(app).get('/api/v1/employee/profile')).status, 401);

  assert.strictEqual((await pay(tokens.emp)).status, 403);
  assert.strictEqual((await pay(tokens.mgr)).status, 201);
  assert.strictEqual((await pay(tokens.sa)).status, 201);

  assert.strictEqual((await del(tokens.emp, 4)).status, 403);
  assert.strictEqual((await del(tokens.mgr, 4)).status, 403);
  assert.strictEqual((await del(tokens.sa, 4)).status, 200);
});

test('tenant isolation: Globex manager cannot approve Acme payroll', async () => {
  const t = (await login('manager@globex.dev', 'Manager@123')).body.accessToken;
  const r = await request(app).post('/api/v1/payroll/approve').set('Authorization', `Bearer ${t}`).send({ employeeId: 3, month: '2026-10', amount: 1 });
  assert.strictEqual(r.status, 403);
});

test('sanitization: NoSQL operators and XSS stripped, SQLi harmless', async () => {
  const nosql = await login({ $gt: '' }, { $ne: null });
  assert.strictEqual(nosql.status, 400);
  const sqli = await login("' OR 1=1 --@x.dev", "' OR '1'='1");
  assert.ok([400, 401].includes(sqli.status));
  const xss = await request(app).post('/api/v1/auth/register').send({ name: '<script>alert(1)</script>Bob', email: 'bob@x.dev', password: 'Strong@123' });
  assert.strictEqual(xss.status, 201);
  assert.strictEqual(xss.body.user.name, 'Bob');
});

test('helmet headers and strict CORS', async () => {
  const r = await request(app).get('/health');
  assert.ok(r.headers['content-security-policy']);
  assert.ok(r.headers['strict-transport-security']);
  assert.strictEqual(r.headers['x-powered-by'], undefined);
  const evil = await request(app).get('/api/v1/employee/profile').set('Origin', 'https://evil.com');
  assert.strictEqual(evil.status, 403);
  assert.strictEqual(evil.headers['access-control-allow-origin'], undefined);
});

test('account lockout / rate limit after 5 failed attempts', async () => {
  const statuses = [];
  for (let i = 0; i < 7; i++) statuses.push((await login('new@y.dev', 'Wrong@123')).status);
  assert.deepStrictEqual(statuses.slice(0, 5), [401, 401, 401, 401, 401]);
  assert.ok([423, 429].includes(statuses[5]));
  // even the CORRECT password is blocked now
  assert.ok([423, 429].includes((await login('new@y.dev', 'Strong@123')).status));
});
