# 🛡️ Enterprise Multi-Tenant Security Gateway
## Screenshots:
<img width="1917" height="882" alt="Screenshot 2026-10-07 102414" src="https://github.com/user-attachments/assets/60b38959-74b4-4b3a-a279-16067e6ee2b0" />
<img width="1917" height="882" alt="Screenshot 2026-10-07 102333" src="https://github.com/user-attachments/assets/40ccdb8a-e885-40a4-9721-f4a7208e5bf2" />
<img width="1917" height="877" alt="Screenshot 2026-10-07 102309" src="https://github.com/user-attachments/assets/0a8eb257-5a4d-41c4-bc16-3a22f47e459f" />


**CSC337 – Advanced Web Technologies · Lab Assignment 05**
Ahmar Ali Murtaza · SP24-BSE-003 · COMSATS University Islamabad, Vehari Campus

A production-grade authentication & authorization gateway built with **Node.js + Express**, implementing
Hybrid Authentication (Local **Bcrypt** + **GitHub OAuth 2.0**), **Access/Refresh Token Rotation** with httpOnly cookies,
**Role-Based Access Control**, tenant isolation, and **OWASP** hardening.

🔗 **Live demo:** https://secure-gateway-3g7o.onrender.com
📬 **Postman collection:** [`postman/SecurityGateway.postman_collection.json`](postman/SecurityGateway.postman_collection.json)

---

## 🔑 Test Credentials

| Role | Email | Password | Tenant |
|---|---|---|---|
| **SuperAdmin** | `superadmin@gateway.dev` | `SuperAdmin@123` | Acme Corp |
| **Manager** | `manager@gateway.dev` | `Manager@123` | Acme Corp |
| **Employee** | `employee@gateway.dev` | `Employee@123` | Acme Corp |
| Employee (delete target) | `employee2@gateway.dev` | `Employee@123` | Acme Corp |
| Employee (lockout demo) | `lockme@gateway.dev` | `Employee@123` | Acme Corp |
| Manager (other tenant) | `manager@globex.dev` | `Manager@123` | Globex Inc |

> Accounts are seeded automatically on every server start (idempotent). GitHub login creates a new `Employee`.

---

## ✅ Requirement Checklist

| # | Requirement | Implementation | File |
|---|---|---|---|
| 1 | Register / Login | `POST /api/v1/auth/register`, `POST /api/v1/auth/login` | `src/routes/auth.js` |
| 1 | Salted hashing | **bcrypt**, cost factor 12 (salt auto-generated per password) | `src/routes/auth.js` |
| 1 | Rate limiting | `express-rate-limit`: **5 failed attempts / 15 min** per IP+email (successful logins not counted) | `src/middleware/rateLimit.js` |
| 1 | Account lockout | DB-level: 5 failures → account locked 15 min (`423 Locked`) | `src/routes/auth.js` |
| 2 | Social login | **GitHub OAuth 2.0** (authorization code flow + `state` CSRF check) | `src/routes/auth.js` |
| 2 | Profile sync | Match by GitHub id → link by verified email → else create; name & avatar synced each login | `src/routes/auth.js` |
| 3 | Access token | JWT HS256, **15 min**, sent as `Authorization: Bearer` | `src/utils/tokens.js` |
| 3 | Refresh token | JWT, **7 days**, cookie `httpOnly; Secure; SameSite=Strict; Path=/api/v1/auth` | `src/utils/tokens.js` |
| 3 | Rotation | `POST /api/v1/auth/refresh` issues a new refresh token & revokes the old one | `src/utils/tokens.js` |
| 3 | Reuse detection | Re-using an old refresh token revokes the **entire token family** | `src/utils/tokens.js` |
| 3 | Revocation on logout | Refresh family revoked in DB + access token `jti` added to denylist | `src/routes/auth.js` |
| 4 | RBAC middleware | `checkRole(['SuperAdmin'])` — role read fresh from DB on every request | `src/middleware/auth.js` |
| 4 | Route matrix | see table below | `src/routes/api.js` |
| 5 | Helmet | CSP, HSTS, X-Frame-Options, noSniff, Referrer-Policy, hides `X-Powered-By` | `src/app.js` |
| 5 | Strict CORS | Whitelist from `CORS_ORIGINS`, unknown origins → `403` | `src/app.js` |
| 5 | Injection / XSS | Drops `$` / `.` keys (NoSQL), prototype-pollution keys, strips HTML (xss), **prepared statements** for SQL, **zod** strict schemas | `src/middleware/sanitize.js`, `src/utils/validate.js` |

### RBAC Route Access Matrix

| Endpoint | SuperAdmin | Manager | Employee | No token |
|---|:-:|:-:|:-:|:-:|
| `GET /api/v1/employee/profile` | ✅ 200 | ✅ 200 | ✅ 200 | ❌ 401 |
| `POST /api/v1/payroll/approve` | ✅ 201 | ✅ 201 (own tenant) | ❌ 403 | ❌ 401 |
| `DELETE /api/v1/users/:id` | ✅ 200 | ❌ 403 | ❌ 403 | ❌ 401 |
| `GET /api/v1/users` | ✅ all | ✅ own tenant | ❌ 403 | ❌ 401 |
| `PATCH /api/v1/users/:id/role` | ✅ | ❌ 403 | ❌ 403 | ❌ 401 |
| `GET /api/v1/audit` | ✅ | ❌ 403 | ❌ 403 | ❌ 401 |

---

## 🏗️ Architecture

```
Browser / Postman
   │  Authorization: Bearer <access 15m>      Cookie: refresh_token (httpOnly, Secure, SameSite=Strict, 7d)
   ▼
helmet → CORS whitelist → body limit (10kb) → cookieParser → sanitize → rate limit
   │
   ├── /api/v1/auth/*   register · login · refresh (rotate) · logout (revoke) · me · github · github/callback
   └── /api/v1/*        authenticate (JWT + denylist) → checkRole([...]) → zod validate → handler
                                                         │
                                               SQLite (better-sqlite3, prepared statements)
                                               tenants · users · refresh_tokens (sha256 only) ·
                                               revoked_access_tokens · payroll_approvals · audit_log
```

### Token flow
1. **Login** → response body has `accessToken`; response sets `refresh_token` httpOnly cookie.
2. Client calls APIs with `Authorization: Bearer <accessToken>`.
3. Access token expires (15 min) → `POST /api/v1/auth/refresh` (cookie sent automatically) → **new access token + new refresh cookie**, old refresh token revoked.
4. If an **old** refresh token is replayed → token theft assumed → whole family revoked → user must log in again.
5. **Logout** → refresh family revoked, access token denylisted, cookie cleared.

### OAuth flow (GitHub)
`/api/v1/auth/github` → random `state` stored in a short-lived httpOnly cookie → GitHub consent →
`/api/v1/auth/github/callback` verifies `state` (timing-safe), exchanges `code`, fetches profile + verified email,
syncs user, issues **our own** refresh cookie, redirects to `/dashboard.html`, which calls `/refresh` for an access token.
No token ever appears in a URL.

---

## 🚀 Run Locally

```bash
git clone https://github.com/ahmaralimurtaza-coder/secure-gateway.git
cd secure-gateway
npm install
cp .env.example .env      # fill GITHUB_CLIENT_ID / SECRET for OAuth (optional locally)
npm start                 # http://localhost:3000
npm test                  # 10 automated security tests
```

For local GitHub OAuth, create an OAuth App with callback `http://localhost:3000/api/v1/auth/github/callback`.

## ☁️ Deploy on Render

1. Push this repo to GitHub (public).
2. Render → **New → Blueprint** → select the repo (uses `render.yaml`; JWT secrets are auto-generated).
3. Set env vars: `APP_URL` and `CORS_ORIGINS` = `https://<your-app>.onrender.com`.
4. GitHub → Settings → Developer settings → **OAuth Apps → New**
   - Homepage URL: `https://<your-app>.onrender.com`
   - Callback URL: `https://<your-app>.onrender.com/api/v1/auth/github/callback`
   - Copy Client ID / Secret into Render env vars `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`.
5. Redeploy. HTTPS is automatic.

> Free Render instances use an ephemeral disk: the SQLite DB resets on redeploy and test accounts are re-seeded automatically.

---

## 🎤 Viva Demo Script (Postman)

Import `postman/SecurityGateway.postman_collection.json` and set `baseUrl` to the live URL.

| Demo | Steps | Expected |
|---|---|---|
| **OAuth login** | Open live URL → *Continue with GitHub* → authorize | Dashboard shows GitHub name, avatar, role `Employee`, provider `github` |
| **Token rotation** | *Login as Employee* → *Refresh (rotation)* twice → check **Cookies** tab | `refresh_token` value changes each time, new `accessToken` |
| **Reuse detection** | Copy `refresh_token` cookie value → Refresh → set the old value back in Cookies → Refresh | `401 Refresh token reuse detected` |
| **Logout revocation** | *Logout* → *GET employee/profile* with old token | `401 Invalid or revoked access token` |
| **Rate limit / lockout** | *Brute force* request × 6 | 5 × `401`, then `429 Too Many Requests` (even with correct password) |
| **RBAC rejection** | *Login as Employee* → *POST payroll/approve* | `403 Role 'Employee' is not allowed` |
| | *Login as Manager* → *DELETE users/:id* | `403` |
| | *Login as SuperAdmin* → *DELETE users/:id* | `200` |
| **Tenant isolation** | Login `manager@globex.dev` → approve payroll for employee 3 | `403 Cross-tenant access denied` |
| **Injection / XSS** | Folder *3. Attacks* | `400` validation errors; XSS name stored as `Bob` |
| **Headers** | Any response → Headers tab | `Content-Security-Policy`, `Strict-Transport-Security`, no `X-Powered-By` |

---

## 🔒 Additional Security Measures
- Self-registration can never set a role (`.strict()` schema rejects extra fields → no privilege escalation).
- Strong password policy (8–72 chars, upper, lower, digit, special).
- Constant-time login: bcrypt compare runs even for unknown emails (no user enumeration via timing).
- Refresh tokens stored as **SHA-256 hashes** only.
- JWT algorithm pinned to HS256 (no `alg: none` attacks).
- Access tokens kept in **memory** on the frontend (never `localStorage`).
- 10 kb body limit, generic 500 errors (no stack traces), audit log for lockouts, RBAC denials and token reuse.

## 📁 Project Structure
```
src/
  app.js                 Express app + Helmet + CORS + middleware chain
  server.js              Entry point (seeds test accounts)
  seed.js                Test accounts
  config/env.js, db.js   Config + SQLite schema
  middleware/auth.js     authenticate + checkRole (RBAC)
  middleware/rateLimit.js
  middleware/sanitize.js NoSQL / XSS / prototype pollution
  routes/auth.js         Local + GitHub OAuth + refresh + logout
  routes/api.js          Protected business routes
  utils/tokens.js        JWT issue / rotate / revoke
  utils/validate.js      zod schemas
public/                  Minimal frontend (login + RBAC dashboard)
postman/                 Postman collection
tests/                   node:test + supertest security tests
```

## 🧪 Tests
```
✔ passwords are bcrypt hashed, never plain text
✔ register: weak password rejected, role cannot be injected
✔ login sets httpOnly + Secure + SameSite=Strict refresh cookie
✔ refresh token rotation + reuse detection
✔ logout revokes refresh and access tokens
✔ RBAC route matrix
✔ tenant isolation: Globex manager cannot approve Acme payroll
✔ sanitization: NoSQL operators and XSS stripped, SQLi harmless
✔ helmet headers and strict CORS
✔ account lockout / rate limit after 5 failed attempts
```
