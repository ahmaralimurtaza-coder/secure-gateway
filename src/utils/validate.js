const { z } = require('zod');

const password = z.string()
  .min(8, 'Password must be at least 8 characters')
  .max(72, 'Password must be at most 72 characters')   // bcrypt input limit
  .regex(/[a-z]/, 'Password needs a lowercase letter')
  .regex(/[A-Z]/, 'Password needs an uppercase letter')
  .regex(/\d/, 'Password needs a digit')
  .regex(/[^A-Za-z0-9]/, 'Password needs a special character');

const schemas = {
  register: z.object({
    name: z.string().min(2).max(80),
    email: z.string().email().max(120).transform((e) => e.toLowerCase()),
    password,
    tenant: z.string().min(2).max(60).optional(),
  }).strict(),
  login: z.object({
    email: z.string().email().transform((e) => e.toLowerCase()),
    password: z.string().min(1).max(72),
  }).strict(),
  payrollApprove: z.object({
    employeeId: z.coerce.number().int().positive(),
    month: z.string().regex(/^\d{4}-(0[1-9]|1[0-2])$/, 'month must be YYYY-MM'),
    amount: z.coerce.number().positive().max(10_000_000),
  }).strict(),
  idParam: z.object({ id: z.coerce.number().int().positive() }),
};

/** validate('body', schemas.login) */
const validate = (where, schema) => (req, res, next) => {
  const result = schema.safeParse(req[where]);
  if (!result.success) {
    return res.status(400).json({
      error: 'Validation failed',
      details: result.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
    });
  }
  if (where === 'body') req.body = result.data;
  else req.validated = { ...(req.validated || {}), [where]: result.data };
  next();
};

module.exports = { schemas, validate };
