# Time Tracker — Backend Documentation (Detailed)

This document explains every file in `time-tracker-backend/` at the function and logic level. It includes example requests/responses, important lines to watch, edge cases, recommended fixes, and mapping to frontend calls.

High-level contract
- Inputs: HTTP requests to API endpoints (login, token refresh/verify, reset/update password, log-work, fetch/update work logs).
- Outputs: JSON responses and emails (for reset password). Most endpoints return a status code and JSON body.
- Core data shapes (simplified):
	- users: { id: number, email: string, password: string (hashed), role: 'admin'|'employee', reset_token?: string }
	- work_logs: { id, employee_id, date (YYYY-MM-DD), start_time (ISO/DATETIME), break_start, break_end, finish_time, description }

Important environment variables expected (see `.env`):
- JWT_SECRET — used to sign access and reset tokens
- DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_CONNECTION_LIMIT — MariaDB connection
- EMAIL_USER, EMAIL_PASS — credentials for the nodemailer account

Notes about module system
- Most backend files use ES modules (import/export). `authMiddleware.js` uses CommonJS `module.exports`. Either convert `authMiddleware.js` to ESM or ensure Node is started with compatibility for mixed modules.

Files and function-level details

### `server.js` — main application
File path: `time-tracker-backend/server.js`
Purpose: Sets up Express app, defines API routes, middleware, and server start.

Top-level variables and setup
- `app.use(express.json())` — parse JSON bodies.
- `refreshTokens = []` — in-memory refresh token store (volatile).
- CORS is configured with origin `http://localhost:5173` and credentials allowed.

Functions & logic (annotated):

- authorizeRole(role)
	- Purpose: returns middleware that checks `req.user.role` and blocks access if it doesn't match.
	- Important lines: checks `if (req.user.role !== role)` and returns 403 if mismatch.
	- Edge cases: If `req.user` is missing (shouldn't happen if `authenticateToken` ran), this will throw. Ensure `authenticateToken` always sets `req.user` or modify to handle undefined.

- loginLimiter (express-rate-limit)
	- Purpose: protect login route from brute force by limiting attempts to 10 per 15 minutes per IP.

- POST /api/login
	- Flow:
		1. Validate presence of `email` and `password` in body; return 400 if missing.
		2. Query DB for user by email: `SELECT * FROM users WHERE email = ?`.
		3. If user not found, respond 404.
		4. Compare password using `bcrypt.compare(password, user.password)`.
		5. If valid, generate access token: `jwt.sign({ id, email, role }, JWT_SECRET, { expiresIn: '1h' })`.
		6. Generate refresh token (no expiry configured here): `jwt.sign({ id, email, role }, JWT_SECRET)` and push to `refreshTokens`.
		7. Respond 200 with `{ message, token, refreshToken }`.

	- Example request:
		POST /api/login
		{
			"email": "employee1@example.com",
			"password": "secret"
		}

	- Example success response:
		200 OK
		{
			"message": "Login successful.",
			"token": "<JWT>",
			"refreshToken": "<JWT>"
		}

	- Security notes:
		- Access token is short lived (1 hour). Refresh tokens are not expired and stored in-memory. Best practice: store refresh tokens in DB with expiration and rotate them.
		- Consider setting `aud`/`iss` claims for stronger validation.

- POST /api/verify-token
	- Flow: Accepts { token } in body and attempts `jwt.verify(token, JWT_SECRET)`. Returns 200 with decoded user or 401 on invalid token.
	- Usage: useful for clients to check token validity without triggering protected endpoints.

- POST /api/refresh
	- Flow:
		1. Accepts `{ token }` (the refresh token) in body.
		2. Checks presence in `refreshTokens`. If missing => 403.
		3. Verifies the refresh token using `jwt.verify` and issues a new access token with `expiresIn: '1h'`.

	- Edge cases:
		- No expiry on refresh tokens means they remain valid indefinitely until server restart or manual removal.
		- If tokens are leaked, attacker can mint new access tokens. Persist and invalidate on logout.

- POST /api/reset-password
	- Input: `{ email }`
	- Flow:
		1. Check email presence.
		2. Query `users` table: `SELECT * FROM users WHERE email = ?`.
		3. If user found, create a short-lived reset token: `jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '10m' })`.
		4. Save token in DB: `UPDATE users SET reset_token = ? WHERE email = ?`.
		5. Compose reset link: `http://localhost:5173/update-password?token=${resetToken}` and call `sendEmail(email, subject, text)`.

	- Example email text: includes reset link and mentions 10 minute expiry.

	- Edge cases & recommendations:
		- If the DB update fails, the email should not be sent. Current flow updates DB then calls `sendEmail` — good.
		- Consider logging the reset token only for audit (not necessary in production).

- POST /api/update-password
	- Input: `{ token, newPassword }`
	- Flow:
		1. Verify token via `jwt.verify(token, JWT_SECRET)` to get `decoded.id`.
		2. Hash `newPassword` via `bcrypt.hash(newPassword, 10)`.
		3. `UPDATE users SET password = ?, reset_token = NULL WHERE id = ?`.
		4. Return success if affectedRows > 0.

	- Error handling: If token invalid/expired, verify will throw; response will be 500 with message 'Invalid or expired token.' — consider returning 401 to indicate authentication error.

- POST /api/log-work
	- Purpose: Employee logs an action (Start Work, Break Start, Break End, Finish Work).
	- Input: `{ employeeId, type }`.
	- Flow (server-side timestamping):
		1. Validate `employeeId` and `type`.
		2. Determine `currentTime` using `new Date()` (server time).
		3. Get `currentDate` as YYYY-MM-DD to find today's log.
		4. Query existing work_log for employee/date: `SELECT * FROM work_logs WHERE employee_id = ? AND date = ?`.
		5. If exists: update appropriate field depending on `type`.
			 - `Start Work` -> `start_time`
			 - `Break Start` -> `break_start`
			 - `Break End` -> `break_end`
			 - `Finish Work` -> `finish_time`
			 Build `SET` clause dynamically and `UPDATE work_logs SET ${setClause} WHERE id = ?`.
		6. If not exists and `type === 'Start Work'`: insert a new row with `start_time`.
		7. If not exists and `type !== 'Start Work'`: return 400 (Start Work required first).

	- Example payloads:
		POST /api/log-work
		{
			"employeeId": 11,
			"type": "Start Work"
		}

	- Edge cases and race conditions:
		- Two requests near-simultaneously could cause duplicate inserts or lost updates. Consider DB transactions or unique constraints on (employee_id, date).
		- Timezone: `currentTime` is server local time; recommended to store in UTC (use `new Date().toISOString()`) and normalize on UI.

- GET /api/work-logs/:employeeId
	- Returns all work_logs for given employee id.

- GET /api/work-logs
	- Returns all work_logs (admin endpoint). Includes debug console logs in current code.

- PUT /api/work-logs/:id
	- Purpose: Edit a work log by ID. Body supports `start_time`, `break_start`, `break_end`, `finish_time`.
	- Flow:
		1. Fetch existing row by id.
		2. Use existing values for unspecified fields, then update with provided ones.
		3. `UPDATE work_logs SET start_time = ?, break_start = ?, break_end = ?, finish_time = ? WHERE id = ?`.

	- Edge cases:
		- Input time formats must match DB expectations (ISO string or DATETIME). Frontend passes ISO string via `convertToISO` in AdminDashboard.

- GET /api/employee/work-logs
	- Extracts employeeId from `req.user.id` (decoded token) and returns that user's work logs.

- GET /api/work-log
	- Returns today's work log for the authenticated user using server date `new Date().toISOString().split('T')[0]`.

- Error handling middleware
	- Receives thrown errors and responds with `err.status || 500` and `err.message`.

Important implementation notes and recommended fixes
- Persist refresh tokens: move refreshTokens from memory to DB with expiry and rotation.
- Module system consistency: convert `authMiddleware.js` to ESM (use `export default function authenticateToken(...) {}`) to avoid mixed module pitfalls.
- Token verification errors: prefer consistent HTTP status codes (401 for invalid credentials, 403 for forbidden). `update-password` currently returns 500 for invalid token — change to 401/400.
- Add DB unique constraint on `(employee_id, date)` to prevent duplicate work_log rows per day. Use transactions for read-modify-write sequences.
- Use UTC for all stored timestamps: `new Date().toISOString()` and interpret on frontend for user's timezone.

Performance & security considerations
- Use parameterized queries (already using `?` placeholders) — good.
- Limit returned rows for admin endpoints (pagination) to prevent large responses.

Files: deeper summaries

#### `login.js`
- Redundant login snippet — duplicate of server's login. Contains a hardcoded `JWT_SECRET` constant; likely leftover. Remove or merge.

#### `authMiddleware.js`
- Function `authenticateToken(req, res, next)`:
	- Reads `Authorization` header, splits by space to extract token.
	- Calls `jwt.verify(token, process.env.JWT_SECRET, (err, user) => ...)` and attaches `req.user = user`.

	- Important: This middleware uses callback-style `jwt.verify`. If you prefer promises, you can use `jwt.verify` wrapped in Promise.

	- Recommended change: convert to ESM and handle missing token with `return res.status(401)`.

#### `db.js`
- Exports a MariaDB pool. When getting connections in the code, most calls call `await pool.getConnection()` and then `conn.release()` — ensure `release()` always runs even on error (use try/finally around DB interactions).

#### `emailService.js`
- Exports `sendEmail(to, subject, text)` using nodemailer.
	- It configures transporter with Gmail and `EMAIL_USER`/`EMAIL_PASS`.
	- Important: For Gmail, enable app password or OAuth2 (recommended) instead of raw password.

#### `hash_password.js` and `insert_test_work_log.js` and `test-db.js`
- Utility scripts used during dev. Keep them out of production deployment and ensure `insert_test_work_log.js` is never run against prod DB without safeguards.

Example curl calls (quick reference)
- Login
	curl -X POST http://localhost:5000/api/login -H "Content-Type: application/json" -d '{"email":"x","password":"y"}'
- Verify token
	curl -X POST http://localhost:5000/api/verify-token -H "Content-Type: application/json" -d '{"token":"<JWT>"}'
- Log work (authenticated)
	curl -X POST http://localhost:5000/api/log-work -H "Content-Type: application/json" -H "Authorization: Bearer <JWT>" -d '{"employeeId":11,"type":"Start Work"}'

Where this maps to frontend
- Base URL expected by frontend: `http://localhost:5000` (see `time-tracker-frontend/src/services/api.js`). Endpoints used by frontend are documented alongside route descriptions above.

---

If you'd like, I can now update `authMiddleware.js` to ESM, add a `.env.example`, and add a simple test script to verify token flows. Tell me which of these you'd like me to do next.
