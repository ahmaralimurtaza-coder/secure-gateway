const express = require('express');
const { z } = require('zod');
const db = require('../config/db');
const { authenticate, checkRole } = require('../middleware/auth');
const { schemas, validate } = require('../utils/validate');

const router = express.Router();
const ALL = ['SuperAdmin', 'Manager', 'Employee'];

router.use(authenticate); // everything below needs a valid access token

// GET /api/v1/employee/profile → all authenticated roles
router.get('/employee/profile', checkRole(ALL), (req, res) => {
  const profile = db.prepare(`
    SELECT u.id, u.name, u.email, u.role, u.provider, u.avatar_url AS avatarUrl, u.created_at AS createdAt,
           t.id AS tenantId, t.name AS tenantName
    FROM users u JOIN tenants t ON t.id = u.tenant_id WHERE u.id = ?`).get(req.user.id);
  const payroll = db.prepare(
    'SELECT month, amount, approved_at AS approvedAt FROM payroll_approvals WHERE employee_id = ? ORDER BY approved_at DESC LIMIT 12'
  ).all(req.user.id);
  res.json({ profile, payroll });
});

// POST /api/v1/payroll/approve → Manager and SuperAdmin only
router.post('/payroll/approve', checkRole(['Manager', 'SuperAdmin']), validate('body', schemas.payrollApprove), (req, res) => {
  const { employeeId, month, amount } = req.body;
  const employee = db.prepare('SELECT id, name, tenant_id FROM users WHERE id = ?').get(employeeId);
  if (!employee) return res.status(404).json({ error: 'Not Found', message: 'Employee not found' });

  // Tenant isolation: a Manager can only approve payroll inside their own tenant.
  if (req.user.role === 'Manager' && employee.tenant_id !== req.user.tenant_id) {
    return res.status(403).json({ error: 'Forbidden', message: 'Cross-tenant access denied' });
  }
  const { lastInsertRowid } = db.prepare(
    'INSERT INTO payroll_approvals (tenant_id, employee_id, month, amount, approved_by) VALUES (?, ?, ?, ?, ?)'
  ).run(employee.tenant_id, employee.id, month, amount, req.user.id);
  db.prepare('INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.id, 'PAYROLL_APPROVED', `employee=${employee.id} month=${month} amount=${amount}`, req.ip);
  res.status(201).json({
    message: 'Payroll approved',
    approval: { id: lastInsertRowid, employeeId: employee.id, employeeName: employee.name, month, amount, approvedBy: req.user.email },
  });
});

// GET /api/v1/users → Manager (own tenant) and SuperAdmin (all) — handy for the demo
router.get('/users', checkRole(['Manager', 'SuperAdmin']), (req, res) => {
  const base = 'SELECT id, name, email, role, provider, tenant_id AS tenantId FROM users';
  const users = req.user.role === 'SuperAdmin'
    ? db.prepare(`${base} ORDER BY id`).all()
    : db.prepare(`${base} WHERE tenant_id = ? ORDER BY id`).all(req.user.tenant_id);
  res.json({ count: users.length, users });
});

// PATCH /api/v1/users/:id/role → SuperAdmin only (e.g. promote a new OAuth user)
router.patch('/users/:id/role', checkRole(['SuperAdmin']), validate('params', schemas.idParam),
  validate('body', z.object({ role: z.enum(['SuperAdmin', 'Manager', 'Employee']) }).strict()), (req, res) => {
    const { id } = req.validated.params;
    const r = db.prepare('UPDATE users SET role = ? WHERE id = ?').run(req.body.role, id);
    if (!r.changes) return res.status(404).json({ error: 'Not Found', message: 'User not found' });
    res.json({ message: `User ${id} is now ${req.body.role}` });
  });

// DELETE /api/v1/users/:id → SuperAdmin only
router.delete('/users/:id', checkRole(['SuperAdmin']), validate('params', schemas.idParam), (req, res) => {
  const { id } = req.validated.params;
  if (id === req.user.id) return res.status(400).json({ error: 'Bad Request', message: 'You cannot delete your own account' });
  const target = db.prepare('SELECT id, email FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: 'Not Found', message: 'User not found' });
  db.prepare('DELETE FROM users WHERE id = ?').run(id); // cascades refresh tokens
  db.prepare('INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.id, 'USER_DELETED', target.email, req.ip);
  res.json({ message: `User ${target.email} deleted` });
});

// GET /api/v1/audit → SuperAdmin only (shows lockouts, RBAC denials, token reuse)
router.get('/audit', checkRole(['SuperAdmin']), (_req, res) => {
  res.json({ logs: db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 100').all() });
});

module.exports = router;
