# Time Tracker — Frontend Documentation (Detailed)

This document explains every file in `time-tracker-frontend/` at the function and component level. It includes example payloads, edge cases, and recommended fixes to make the app production-ready.

Overview / Contract
- Inputs: user actions (login, QR scans, editing grid cells), stored JWTs in `localStorage` (access + refresh), and API responses.
- Outputs: API calls to backend (`/api/*`), UI updates, toasts, and exported files (XLSX).

Important front-end conventions in this project
- The client stores `token` and `refreshToken` in `localStorage` and uses an Axios instance (`src/services/api.js`) to attach the Bearer token.
- Many components decode the JWT client-side (via `atob`) for role/ID extraction; this is only for UI and must not replace server-side authorization.

Files (detailed)

### `src/services/api.js`
Purpose: axios instance with baseURL `http://localhost:5000`.

Detailed behavior and edge cases:
- The axios instance reads the token from `localStorage` at request time and sets `Authorization: Bearer <token>`.
- Edge cases:
  - If the access token is expired, backend returns 401/403; the app currently doesn't attempt automatic refresh — it should.
  - There is no response interceptor to handle 401 and perform a silent refresh using `refreshToken`.

Suggestion (silent refresh): add a response interceptor that calls `/api/refresh` and retries the failed request once if a new access token is obtained.

Example usage inside app:
```js
const resp = await API.get('/api/work-log');
```

### `src/utils/token.js`
Purpose: decode a JWT payload (UI-only helper).

How it works:
- `decodeToken(token)` uses `JSON.parse(atob(token.split('.')[1]))`.
- This does not verify signature or expiry. Use it only to adapt UI. For auth, rely on server verification.

Recommended addition: `isTokenExpired(token)` that checks `payload.exp` against current time to centralize expiry checks.

### `src/components/Navbar.jsx`
Purpose: global navigation, role-aware links, and logout flow.

Function-level breakdown:
- token reading & decoding: `const token = localStorage.getItem('token')` and `const user = token ? decodeToken(token) : null`.
- `handleLogout()` clears `token` and `refreshToken` from `localStorage` and navigates to `/login`.

Notes & improvements:
- If token exists but is expired, the UI may still show user info. Consider verifying token on load and redirecting to login if invalid.

### `src/components/ProtectedRoute.jsx`
Bug & fixes:
- Currently references helpers (`getUserRole`, `isAuthenticated`) that are defined in `App.jsx` not imported here. This will throw at runtime.

Fix options:
1. Create `src/utils/auth.js` exporting `getUserRole`, `isAuthenticated`, and import it in both `App.jsx` and `ProtectedRoute.jsx`.
2. Move the ProtectedRoute implementation into `App.jsx` (already partially duplicated).

Minimal secure implementation example for `ProtectedRoute`:
```jsx
import { decodeToken } from '../utils/token';
const isAuthenticated = () => { /* check token exists && not expired */ }
const getUserRole = () => { /* decode token -> role */ }
```

### `src/components/QRCodeScanner.jsx` and `QRCodeDisplay.jsx`
QRCodeScanner:
- `handleScan(data)` expects `data.text` containing the scanned string; it calls the `onScan` prop with `data.text`.
- `handleError(error)` logs scan errors; parent displays toasts.

QRCodeDisplay:
- Fetches a QR payload from `http://localhost:5000/generate-qr`. There is no such endpoint in `server.js`. If you need a general QR for the office location, implement `/generate-qr` on server or remove the component.

Format contract for QR payload (expected by `ScannerPage`):
- A JSON string that parses to `{ lat: number, lng: number }` so `JSON.parse(data)` works.

### `src/pages/Login.jsx`
Flow breakdown:
- Uses Formik for form handling and Yup for validation.
- `onSubmit` calls `API.post('/api/login', values)`. On success:
  - Stores `token` and `refreshToken` in `localStorage`.
  - Uses `decodeToken(token)` to get user role and redirects to `/admin` or `/` using `window.location.href`.

Observations and improvements:
- Use SPA navigation (`navigate(...)`) instead of `window.location.href` to avoid full reloads.
- Consider catching network errors (no response) separately from `error.response`.

Security consideration:
- Storing refresh tokens in `localStorage` exposes them to XSS. Use HttpOnly cookies for refresh tokens in production.

### `src/pages/ScannerPage.jsx`
This is the primary Employee interaction page. Core functions:

- useEffect on mount:
  - Redirects to `/login` if no token.
  - Calls `fetchWorkLog()` to get today's log.

- fetchWorkLog():
  - GET `/api/work-log` with Authorization header. If 404, set `workLog` to null.

- handleScan(data):
  - `JSON.parse(data)` to extract `lat/lng` and calls `validateLocation`.
  - If `validateLocation` returns true, sets `isLocationVerified(true)` and shows success toast.

- validateLocation(scannedLocation):
  - Compares scanned coordinates to a hardcoded `userLocation` using Haversine `calculateDistance`.
  - Returns true if distance <= 0.1 km.

- handleAction(type):
  - Validates allowed transitions based on `workLog` (start, break start/end, finish) to prevent illegal state changes.
  - Extracts `employeeId` from decoded token payload and posts `{ employeeId, type }` to `/api/log-work`.

Improvements:
- Replace hardcoded `userLocation` with real device geolocation or server-side verification.
- Let backend infer `employeeId` from token — don't pass it from client (reduces trusted input surface).

### `src/pages/EmployeeDashboard.jsx`
Helpers and logic:
- `fetchWorkLogs` loads `/api/employee/work-logs` and sets `workLogs`.
- `formatTime`, `calculateWorkedHours`, `calculateBreakMinutes` are pure helpers used to convert DB datetimes to friendly strings.

Edge cases:
- If DB stores dates in UTC, `new Date(datetime)` will convert to local timezone. That's correct for display but be explicit in server docs.

### `src/pages/AdminDashboard.jsx`
Core behaviors:
- Loads all work logs via `/api/work-logs`.
- Renders AG Grid with editable time columns. `onCellValueChanged` performs basic validation and opens a confirm modal.
- `handleModalConfirm` maps user-selected label to ISO datetime and calls `PUT /api/work-logs/:id`.
- Download uses `XLSX` to export filtered rows or all rows.

Important edge cases:
- Timezone handling: `convertToISO` uses local timezone offset adjustments; validate in your timezone.
- UX: `window.location.reload()` is used after edits — consider re-fetching data instead.

### `src/pages/ResetPassword.jsx` & `src/pages/UpdatePassword.jsx`
ResetPassword:
- `POST /api/reset-password` with `{ email }`. Shows the response message.

UpdatePassword:
- Extracts `token` from query params and `POST /api/update-password` with `{ token, newPassword }`.

Security notes:
- Reset token is passed via query string. Query strings may be logged by third-parties; optionally use one-time server-side stored tokens and a POST-based confirmation flow.

Other small files
- `src/main.jsx` mounts the app; `src/index.js` imports MUI styles.

Bugs and recommended fixes (prioritized)
1. Fix `ProtectedRoute.jsx` by creating `src/utils/auth.js` and importing shared helpers.
2. Implement silent token refresh in `src/services/api.js` to improve UX and reliability.
3. Remove/merge duplicate `login.js` on backend and convert `authMiddleware.js` to ESM.
4. Replace passing `employeeId` from client to server — derive from token server-side.

Example snippet: suggested silent-refresh in `src/services/api.js`
```js
API.interceptors.response.use(
  res => res,
  async err => {
    if (err.response?.status === 401) {
      const refreshToken = localStorage.getItem('refreshToken');
      if (refreshToken) {
        try {
          const r = await axios.post('http://localhost:5000/api/refresh', { token: refreshToken });
          localStorage.setItem('token', r.data.token);
          err.config.headers['Authorization'] = `Bearer ${r.data.token}`;
          return axios(err.config);
        } catch (refreshErr) {
          // Refresh failed -> force logout
          localStorage.removeItem('token');
          localStorage.removeItem('refreshToken');
          window.location.href = '/login';
        }
      }
    }
    return Promise.reject(err);
  }
)
```

How frontend maps to backend endpoints (concise)
- `API.post('/api/login')` => `server.js POST /api/login`
- `API.post('/api/reset-password')` => `server.js POST /api/reset-password`
- `API.post('/api/update-password')` => `server.js POST /api/update-password`
- `API.post('/api/log-work')` => `server.js POST /api/log-work`
- `API.get('/api/work-log')` => `server.js GET /api/work-log`
- `API.get('/api/employee/work-logs')` => `server.js GET /api/employee/work-logs`
- `API.get('/api/work-logs')` => `server.js GET /api/work-logs`
- `API.put('/api/work-logs/:id')` => `server.js PUT /api/work-logs/:id`

---

If you'd like, I can implement any of the prioritized fixes above (for example, create `src/utils/auth.js` and patch `ProtectedRoute.jsx` and `App.jsx`, or add the silent refresh interceptor). Tell me which one to do next and I'll make the change and run a quick test.
