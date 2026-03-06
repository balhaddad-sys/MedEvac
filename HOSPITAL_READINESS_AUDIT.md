# MedEvac Hospital Emergency Readiness Audit

**Date:** 2026-03-06
**Auditor:** Automated Code Audit
**Application:** MedEvac - Patient Registry PWA
**Target Environment:** Mubarak Al-Kabeer Hospital Emergency Departments

---

## Executive Summary

**Overall Readiness: NOT READY for hospital emergency use**

MedEvac is a well-designed PWA with solid offline-first architecture and a clean, mobile-optimized UI. However, it has **critical security vulnerabilities**, **zero test coverage**, **no audit logging**, and **missing HIPAA/healthcare compliance measures** that make it unsuitable for production hospital use in its current state.

| Category | Rating | Status |
|----------|--------|--------|
| Security & Authentication | 2/10 | CRITICAL |
| Data Protection & Privacy | 3/10 | CRITICAL |
| HIPAA / Healthcare Compliance | 1/10 | CRITICAL |
| Reliability & Error Handling | 5/10 | NEEDS WORK |
| Offline Capability | 7/10 | ACCEPTABLE |
| Testing & Quality Assurance | 1/10 | CRITICAL |
| UI/UX & Accessibility | 6/10 | NEEDS WORK |
| Deployment & Operations | 5/10 | NEEDS WORK |
| Performance | 7/10 | ACCEPTABLE |

---

## 1. SECURITY & AUTHENTICATION — CRITICAL

### 1.1 Database Rules Are Completely Open (CRITICAL)
**File:** `MAK_Registry/database.rules.json`

```json
"patients": { "$unit": { ".read": true, ".write": true } },
"pins": { ".read": true, ".write": true }
```

**Impact:** ANY person on the internet can read, modify, or delete ALL patient data and ALL PIN codes by directly calling the Firebase REST API. No authentication is required. This is the single most dangerous vulnerability — the entire database is publicly exposed.

**Remediation:** Implement Firebase Authentication. Require authenticated users with role-based access. Database rules must enforce `auth != null` at minimum, and ideally verify claims for department-level access.

### 1.2 API Keys Hardcoded in Client-Side Code (HIGH)
**File:** `MAK_Registry/index.html:265-266`

```javascript
apiKey: "AIzaSyBuuSFWmjkDPiF-LNlZkjVcMDPK9sHyYEQ"
const GK = "AIzaSyA38cYzjTCuh3WPXgVWG6bnNAiygwq9fQ8";  // Gemini API key
```

**Impact:** The Firebase API key is somewhat expected to be public (Firebase restricts via security rules), but the **Gemini AI API key is fully exposed** and can be abused by anyone who views page source, leading to unauthorized API usage and billing.

**Remediation:** Move the Gemini API key to a Firebase Cloud Function (server-side proxy). Add API key restrictions in Google Cloud Console (HTTP referrer restrictions, API restrictions).

### 1.3 PIN-Based Auth Without Real Authentication (CRITICAL)
**File:** `MAK_Registry/index.html:316, 497`

```javascript
const PINS = {A_M:"1111", A_F:"1112", ..., ADMIN:"0000"};
```

- PINs are **hardcoded as defaults** in the JavaScript source (visible to anyone)
- PINs are stored in Firebase with **public read access** — anyone can retrieve all PINs via REST API
- PIN validation happens **entirely client-side** — can be bypassed by modifying JavaScript
- No rate limiting on PIN attempts — brute force is trivial (only 10,000 combinations for 4-digit PINs)
- No account lockout mechanism
- No multi-factor authentication
- Default admin PIN is `0000`

**Remediation:** Implement Firebase Authentication with proper server-side verification. Add rate limiting, account lockout, and consider 2FA for admin access.

### 1.4 Content Security Policy Allows unsafe-inline (MODERATE)
**File:** `MAK_Registry/index.html:11`

```
script-src 'self' 'unsafe-inline' ...
```

The CSP allows `unsafe-inline` scripts, which weakens XSS protection. While necessary for the current inline-script architecture, this is a risk factor.

### 1.5 XSS Vulnerability in HTML Rendering (HIGH)
**File:** `MAK_Registry/index.html:452, 457, etc.`

Patient data (names, notes, wards) is injected directly into HTML via string concatenation without sanitization:

```javascript
'<div class="pn">'+(p.name||"")+'</div>'
```

If a malicious actor injects `<script>` tags or event handlers via the publicly-writable database, it will execute in every user's browser.

**Remediation:** Sanitize all user-provided data before HTML insertion using `textContent` or a sanitization library. Alternatively, use DOM API methods rather than `innerHTML`.

### 1.6 Error Messages Expose Stack Traces (LOW)
**File:** `MAK_Registry/index.html:223-224, 563`

```javascript
showFatal('...'+e.message+'<br><br>'+e.stack+'</div>');
```

Full stack traces are shown to users on error, potentially leaking internal implementation details.

---

## 2. DATA PROTECTION & PRIVACY — CRITICAL

### 2.1 No Data Encryption at Rest (CRITICAL)

- Patient data in Firebase Realtime Database is not encrypted beyond Firebase's default at-rest encryption
- **localStorage stores patient data in plaintext** including civil IDs, names, and medical severity codes
- No client-side encryption of sensitive fields before storage
- Civil ID masking (`mask()` function at line 402) is display-only — full data is stored unmasked

### 2.2 No Transport Layer Pinning (MODERATE)

While HTTPS is used (Firebase enforces TLS), there is no certificate pinning in the iOS or Android app wrappers, making the app vulnerable to MITM attacks with compromised certificates.

### 2.3 Patient Data Survives Session Termination (HIGH)

- `localStorage` persists patient data indefinitely across sessions
- No mechanism to clear cached patient data on logout/lock
- The `beforeunload` handler clears memory state but **not localStorage**
- Another user on the same device can access all previously viewed patient data

### 2.4 No Data Retention Policy Enforcement (MODERATE)

No automated mechanism for data expiration, archival, or deletion of stale patient records.

### 2.5 Backup as PNG Contains All Patient Data (MODERATE)
**File:** `MAK_Registry/index.html:417-430`

The backup feature exports all patient data (including full civil IDs) as a PNG image saved to the user's device with no encryption or access control.

---

## 3. HIPAA / HEALTHCARE COMPLIANCE — CRITICAL

### 3.1 No Audit Logging (CRITICAL)

**There is zero audit logging in the entire application.** Healthcare regulations require:
- Who accessed what patient data and when
- Who modified patient records
- Failed access attempts
- Data export events
- Admin configuration changes

### 3.2 No User Identity Management (CRITICAL)

- Users are identified only by department PINs, not individual accounts
- Impossible to trace actions to specific individuals
- Shared PINs across all staff in a department violates healthcare accountability requirements

### 3.3 No Access Control Granularity (HIGH)

- A department PIN grants full read/write access to that department's data
- No read-only roles for observers
- No role differentiation (nurse vs. doctor vs. administrator)
- Admin has access to everything with no restrictions

### 3.4 No BAA (Business Associate Agreement) Evidence (HIGH)

No documentation of BAA with Google/Firebase for handling PHI (Protected Health Information).

### 3.5 No Data Processing Agreement (MODERATE)

Patient images sent to Gemini AI for OCR are processed by Google with no documented data processing agreement for healthcare data.

### 3.6 Missing Consent Mechanisms (MODERATE)

No patient consent tracking for data collection and processing.

---

## 4. RELIABILITY & ERROR HANDLING — NEEDS WORK

### 4.1 Single Point of Failure: Firebase (HIGH)

- Complete dependency on Firebase Realtime Database
- No database failover configuration
- No health check or heartbeat monitoring
- If Firebase goes down during an emergency, new data entry fails (offline queue helps but has limits)

### 4.2 Offline Queue Has No Conflict Resolution (MODERATE)
**File:** `MAK_Registry/index.html:287-298`

```javascript
async function syncQueue() {
  for (const op of q) {
    try {
      if (op.type === "set") await set(ref(db, op.path), op.data);
      ...
```

- No conflict resolution for concurrent edits
- Last-write-wins can overwrite critical updates made by other staff
- No versioning or optimistic concurrency control
- Failed operations stay in queue indefinitely without alerting the user

### 4.3 No Data Validation on Client (HIGH)
**File:** `MAK_Registry/index.html:487`

- Minimal input validation (only checks non-empty for required fields)
- No validation of civil ID format or checksum
- No ward/bed format validation
- Severity code accepted as any value from the UI but no server-side enforcement
- Firebase `.validate` rule only checks for field existence, not format

### 4.4 Global Error Handlers Show Fatal Errors (MODERATE)

The `window.onerror` and `window.onunhandledrejection` handlers display raw error messages to users and provide no recovery mechanism.

### 4.5 No Graceful Degradation for OCR (LOW)

If the Gemini API is down or returns malformed data, the OCR feature fails with a generic error. No fallback mechanism for manual data entry from images.

---

## 5. OFFLINE CAPABILITY — ACCEPTABLE

### 5.1 Strengths
- Service Worker with proper caching strategies (network-first for HTML, cache-first for assets)
- localStorage-based offline queue for data operations
- Automatic sync when back online
- Offline status indicator in the UI
- Instant render from cached data

### 5.2 Weaknesses
- localStorage has a ~5-10MB limit per origin — could be exceeded with large patient datasets
- No IndexedDB fallback for larger offline storage
- Service Worker cache version (`mak-v10`) requires manual bumping
- No background sync API usage (could use Background Sync for more reliable queue processing)

---

## 6. TESTING & QUALITY ASSURANCE — CRITICAL

### 6.1 Zero Test Coverage (CRITICAL)

**There are no test files whatsoever** — no unit tests, no integration tests, no end-to-end tests, no smoke tests.

For a hospital emergency application, this is unacceptable. Critical paths that must be tested:
- PIN authentication flow
- Patient CRUD operations (add, edit, delete)
- Offline queue and sync
- Data filtering and search
- OCR import pipeline
- Backup export
- Auto-lock/privacy screen
- Concurrent access scenarios

### 6.2 No Linting or Code Quality Tools

- No ESLint, Prettier, or any code quality configuration
- No TypeScript (entire app is untyped vanilla JS)
- No static analysis

### 6.3 No Load/Stress Testing

No evidence of performance testing under load (e.g., hundreds of concurrent users during a mass casualty event).

---

## 7. UI/UX & ACCESSIBILITY — NEEDS WORK

### 7.1 Strengths
- Clean, mobile-first responsive design
- Color-coded severity system (green/yellow/red)
- RTL Arabic support
- PWA install prompts for both iOS and Android
- Auto-lock for privacy
- Privacy blur screen when app is backgrounded

### 7.2 Weaknesses
- **No ARIA labels** on most interactive elements (buttons, inputs, patient cards)
- **No keyboard navigation** support — essential for accessibility compliance
- **Color-only severity indication** — users with color blindness may not distinguish codes
- `user-scalable=no` prevents pinch-to-zoom — accessibility violation
- No high-contrast/dark mode toggle
- No screen reader support
- Single-column mobile layout — no tablet/desktop optimization
- Max-width of 430px limits usability on larger screens (hospital monitors)

---

## 8. DEPLOYMENT & OPERATIONS — NEEDS WORK

### 8.1 CI/CD Pipeline Present but Minimal

- GitHub Actions deploy to Firebase Hosting on push to `main`
- No staging/preview environments
- No automated testing in the pipeline
- No deployment approvals or rollback mechanisms

### 8.2 No Monitoring or Alerting

- No application performance monitoring (APM)
- No error tracking service (e.g., Sentry)
- No uptime monitoring
- No alerts for database issues or quota limits
- No Firebase usage/billing alerts

### 8.3 No Disaster Recovery Plan

- No automated backups of Firebase database
- No documented recovery procedures
- No failover configuration
- PNG backup is manual and per-unit only

### 8.4 Secrets Management (MODERATE)
**File:** `.github/workflows/build-apk.yml`, `codemagic.yaml`

CI/CD workflows reference secrets properly (`${{ secrets.FIREBASE_TOKEN }}`), but the main application embeds API keys directly in source.

---

## 9. PERFORMANCE — ACCEPTABLE

### 9.1 Strengths
- Lightweight: single HTML file, no heavy frameworks
- Fast initial load (minimal dependencies)
- Efficient re-rendering with direct DOM manipulation
- Firebase real-time listeners for instant updates
- Service Worker for asset caching

### 9.2 Concerns
- Full re-render on every state change (`app.innerHTML = h`) — could cause jank with 100+ patients
- No virtual scrolling for long patient lists
- No lazy loading of images
- `render()` function rebuilds entire DOM tree including re-binding all event listeners

---

## Priority Remediation Roadmap

### Phase 1 — CRITICAL (Must fix before ANY hospital use)

| # | Issue | Effort |
|---|-------|--------|
| 1 | Lock down Firebase database rules — require authentication | 2-3 days |
| 2 | Implement Firebase Authentication (email/password or SSO) | 3-5 days |
| 3 | Move Gemini API key to server-side Cloud Function | 1 day |
| 4 | Sanitize all HTML output to prevent XSS | 1-2 days |
| 5 | Add audit logging for all data access and modifications | 3-5 days |
| 6 | Clear localStorage on logout; encrypt sensitive cached data | 2-3 days |
| 7 | Add individual user accounts (not shared department PINs) | 3-5 days |
| 8 | Write tests for critical paths | 5-10 days |

### Phase 2 — HIGH (Required for compliance)

| # | Issue | Effort |
|---|-------|--------|
| 9 | Role-based access control (RBAC) | 3-5 days |
| 10 | Rate limiting and brute-force protection | 1-2 days |
| 11 | Input validation (civil ID format, ward format) | 1-2 days |
| 12 | Conflict resolution for offline sync | 3-5 days |
| 13 | Establish BAA with Google Cloud / Firebase | Administrative |
| 14 | Automated database backups | 1-2 days |
| 15 | Error monitoring (Sentry or equivalent) | 1 day |

### Phase 3 — MODERATE (Recommended for production)

| # | Issue | Effort |
|---|-------|--------|
| 16 | Accessibility improvements (ARIA, keyboard nav) | 3-5 days |
| 17 | Staging environment and deployment approvals | 1-2 days |
| 18 | Load/stress testing | 2-3 days |
| 19 | Desktop/tablet responsive layout | 2-3 days |
| 20 | Data retention policy enforcement | 1-2 days |
| 21 | Certificate pinning for mobile apps | 1-2 days |
| 22 | Background Sync API for offline queue | 1-2 days |

---

## Conclusion

MedEvac demonstrates a thoughtful approach to emergency patient tracking with its offline-first PWA architecture, intuitive color-coded triage system, and multi-platform deployment. However, it currently operates with **no real security** — the database is publicly accessible, authentication is client-side only, and there is zero audit trail.

**For hospital emergency use where patient safety and data privacy are paramount, this application must not be deployed until at minimum Phase 1 remediation is complete.**

The most critical immediate action is **locking down the Firebase database rules** — right now, anyone who discovers the database URL can read or wipe all patient records without any authentication.
