# MedEvac Emergency Hospital Audit Report — Volume II

**System:** MedEvac — Secure Patient Registry System
**Facility:** Mubarak Al-Kabeer Hospital, Kuwait
**Audit Date:** 2026-03-06
**Audit Type:** Deep Technical & Operational Audit (Line-Level Code Review)
**Predecessor:** EMERGENCY_HOSPITAL_AUDIT.md (Volume I — Structural Assessment)
**Classification:** CONFIDENTIAL — For Authorized Hospital Administration Only

---

## Table of Contents

1. [Scope & Methodology](#1-scope--methodology)
2. [Vulnerability Deep-Dive (Code-Level)](#2-vulnerability-deep-dive-code-level)
3. [Firebase Security Rules — Detailed Exploitation Scenarios](#3-firebase-security-rules--detailed-exploitation-scenarios)
4. [Service Worker & Caching — Attack Surface Analysis](#4-service-worker--caching--attack-surface-analysis)
5. [iOS Native Wrapper — Full Security Review](#5-ios-native-wrapper--full-security-review)
6. [Android TWA — Build Pipeline & Runtime Security](#6-android-twa--build-pipeline--runtime-security)
7. [CI/CD Pipeline Security Audit](#7-cicd-pipeline-security-audit)
8. [Privacy Policy & Legal Compliance Gap Analysis](#8-privacy-policy--legal-compliance-gap-analysis)
9. [Operational Readiness Assessment](#9-operational-readiness-assessment)
10. [Performance & Scalability Analysis](#10-performance--scalability-analysis)
11. [Error Handling & Resilience Audit](#11-error-handling--resilience-audit)
12. [State Management & Data Consistency](#12-state-management--data-consistency)
13. [New Findings Register](#13-new-findings-register)
14. [Combined Risk Heat Map](#14-combined-risk-heat-map)
15. [Detailed Remediation Specifications](#15-detailed-remediation-specifications)

---

## 1. Scope & Methodology

### 1.1 What Changed from Volume I

Volume I provided a structural assessment. This Volume II performs:
- **Line-by-line code review** of every file in the repository (22 files)
- **Exploitation scenario modeling** for each vulnerability
- **CI/CD pipeline security audit** (GitHub Actions + Codemagic)
- **iOS and Android native wrapper deep review**
- **Performance and scalability projections**
- **Operational procedure gap analysis**

### 1.2 Complete File Inventory Reviewed

| # | File | Size | Purpose |
|---|------|------|---------|
| 1 | `MAK_Registry/index.html` | 596 lines | Main application |
| 2 | `MAK_Registry/sw.js` | 65 lines | Service Worker |
| 3 | `MAK_Registry/database.rules.json` | 47 lines | Firebase Security Rules |
| 4 | `MAK_Registry/firebase.json` | 25 lines | Firebase Hosting Config |
| 5 | `MAK_Registry/manifest.json` | 17 lines | PWA Manifest |
| 6 | `MAK_Registry/privacy.html` | 138 lines | Privacy Policy |
| 7 | `MAK_Registry/support.html` | 113 lines | Support/FAQ Page |
| 8 | `MAK_Registry/icon-192.png` | Binary | App icon 192px |
| 9 | `MAK_Registry/icon-512.png` | Binary | App icon 512px |
| 10 | `ios/MedEvac/MedEvac/ViewController.swift` | 194 lines | iOS WebView Controller |
| 11 | `ios/MedEvac/MedEvac/AppDelegate.swift` | 14 lines | iOS Entry Point |
| 12 | `ios/MedEvac/MedEvac/Info.plist` | 120 lines | iOS Configuration |
| 13 | `ios/MedEvac/project.yml` | 65 lines | XcodeGen Configuration |
| 14 | `ios/MedEvac/ExportOptions.plist` | 21 lines | IPA Export Config |
| 15 | `ios/MedEvac/MedEvac/Assets.xcassets/...` | JSON | Asset Catalogs |
| 16 | `.github/workflows/build-apk.yml` | 101 lines | Android CI Pipeline |
| 17 | `.github/workflows/build-ios.yml` | 141 lines | iOS CI Pipeline |
| 18 | `.github/workflows/deploy-web.yml` | 22 lines | Web Deploy Pipeline |
| 19 | `codemagic.yaml` | 335 lines | Codemagic CI/CD |

---

## 2. Vulnerability Deep-Dive (Code-Level)

### 2.1 V-01: Reflected XSS via Error Handlers (NEW — CRITICAL)

**Location:** `index.html:223-224`

```javascript
window.onerror = function(m, s, l, c, e) {
  showFatal('<div style="padding:40px;color:red;font-size:13px;word-break:break-all">' +
    '<b>Error:</b> ' + m + '<br>Line: ' + l + '</div>');
};

window.onunhandledrejection = function(e) {
  showFatal('<div style="padding:40px;color:red;font-size:13px;word-break:break-all">' +
    '<b>Promise Error:</b> ' + (e.reason?.message || e.reason) + '</div>');
};
```

**Vulnerability:** Error messages are injected as raw HTML via `innerHTML` in `showFatal()`. If an attacker can cause a controlled error message (e.g., via a crafted Firebase data value that triggers a parse error), the error message text is rendered as HTML, enabling script injection.

**Exploitation Scenario:**
1. Attacker uses anonymous Firebase auth (trivial)
2. Writes a malformed value to a patient field that causes a parse error
3. Error message containing `<img src=x onerror=alert(1)>` renders as HTML
4. Any user viewing that unit executes attacker's script

**Severity:** CRITICAL
**Fix:** Use `textContent` instead of `innerHTML` in `showFatal()`:
```javascript
function showFatal(msg) {
  const div = document.createElement('div');
  div.style.cssText = 'padding:40px;color:red;font-size:13px;word-break:break-all';
  div.textContent = msg;
  const app = document.getElementById("app");
  if (app) app.replaceChildren(div);
  else document.body.prepend(div);
}
```

### 2.2 V-02: DOM-Based XSS in Confirmation Dialog (NEW — HIGH)

**Location:** `index.html:417`

```javascript
function confirm2(title, msg) {
  return new Promise(res => {
    const r = $("cr");
    r.innerHTML = '...<div style="font-size:15px;font-weight:800;margin-bottom:6px">' +
      title + '</div><div style="font-size:12px;color:var(--muted);margin-bottom:20px">' +
      msg + '</div>...';
  });
}
```

**Vulnerability:** The `title` and `msg` parameters are injected as raw HTML. While current callers use hardcoded strings (`confirm2("Delete?", ...)`), one caller uses:

```javascript
// index.html:498
confirm2("Delete?", 'Remove "' + esc(S.editP.name) + '"?')
```

The `title` is safe (hardcoded), but `msg` uses `esc()` which IS safe. However, this is a fragile pattern — any future caller passing unsanitized data would create an XSS. The function signature implies safety but doesn't enforce it.

**Severity:** HIGH (defense-in-depth failure)
**Fix:** Apply `esc()` inside `confirm2()` itself.

### 2.3 V-03: PIN Plaintext Fallback Enables Bypass (CRITICAL)

**Location:** `index.html:510-514`

```javascript
async function checkPin() {
  const stored = S.pins[S.pinTarget] || PINS[S.pinTarget];
  // Support both hashed and plaintext PINs during migration
  let match = S.pinVal === stored;           // PLAINTEXT COMPARE FIRST
  if (!match) {
    const h = await hashPin(S.pinVal);
    match = h === stored;                    // THEN hash compare
  }
  ...
}
```

**Vulnerability Chain:**
1. Default PINs in `PINS` object are plaintext (e.g., `"1111"`, `"0000"`)
2. Firebase `pins` node is readable by any authenticated (anonymous) user
3. Even if admin changes a PIN, the code falls back to plaintext `PINS` constants if Firebase read fails
4. The `|| PINS[S.pinTarget]` fallback means: if Firebase is unreachable, ALL default PINs work regardless of any admin changes

**Exploitation:** Disable network → app falls back to hardcoded PINs → access any unit.

**Severity:** CRITICAL
**Fix:** Remove the `PINS` fallback entirely. If PIN cannot be loaded from server, deny access.

### 2.4 V-04: Gemini API Key Readable by Any User (MEDIUM)

**Location:** `index.html:273`

```javascript
get(ref(db, "config/geminiKey")).then(s => {
  if (s.exists()) GK = s.val();
}).catch(() => {});
```

**Combined with** `database.rules.json:28-30`:
```json
"config": {
  ".read": "auth != null",
  ".write": false
}
```

**Impact:** Any anonymous user can read the Gemini API key. While the key is not hardcoded in source, it IS exposed to every app client. An attacker could:
- Extract the key via DevTools console: just type `GK`
- Use it for unlimited Gemini API calls billed to the project
- Potentially hit API quotas causing denial of service for OCR feature

**Severity:** MEDIUM
**Fix:** Proxy Gemini requests through a Cloud Function that holds the key server-side.

### 2.5 V-05: localStorage Poisoning via Shared Origin (NEW — MEDIUM)

**Location:** `index.html:276-285`

```javascript
const _ek = "mak_" + btoa(location.hostname).slice(0,8);
```

The encryption key is derived from `location.hostname`. On Firebase Hosting, this is `unit-e-1d07b.web.app`. Any other Firebase project on the same `.web.app` domain shares the same origin policy.

**Wait — correction.** Each Firebase project has its own subdomain, so origins ARE isolated. However, if the app is accessed via both `unit-e-1d07b.web.app` AND `unit-e-1d07b.firebaseapp.com`, the derived keys would differ, causing cached data to become unreadable on the alternate domain.

**Impact:** Patients cached while using one domain cannot be recovered from the other domain. During emergencies, if a URL redirect occurs, offline data appears lost.

**Severity:** MEDIUM
**Fix:** Use a fixed, non-hostname-derived key, or normalize the hostname before derivation.

### 2.6 V-06: Seed Data Contains Real-Looking Patient Records (NEW — HIGH)

**Location:** `index.html:379-380`

```javascript
const SEED_M = [
  {name:"خالد محمد أحمد", civil:"264100700097", nat:"أردني", ward:"W14", code:4, notes:""},
  {name:"عبدالله محمود النجار", civil:"233041500113", nat:"كويتي", ward:"W15", code:3, notes:""},
  ...
];
```

**Issue:** The application ships with 9 hardcoded patient records containing realistic Arabic names and 12-digit civil ID numbers. These are automatically seeded into the production Firebase database on first boot (`seedData()` at line 384).

**Concerns:**
1. If these are REAL patient records, they are PHI hardcoded into public source code — **HIPAA/privacy violation**
2. If they are fictitious, they could be confused with real patients during an emergency
3. The seed function runs on EVERY fresh deployment, potentially polluting production data
4. Civil IDs like `264100700097` follow Kuwait's civil ID format — they could belong to real people

**Severity:** HIGH
**Fix:**
- Confirm whether these are real or fictitious records
- Remove all seed data from client-side code immediately
- If seed data is needed, create it via a secured admin-only setup script
- Never commit PII/PHI to source control

### 2.7 V-07: No Input Sanitization on Firebase Write Paths (NEW — MEDIUM)

**Location:** `index.html:497, 500`

```javascript
// Edit patient
await set(ref(db, "patients/" + S.unit + "/" + S.editP._k), data);

// Add patient
await push(ref(db, "patients/" + S.unit), data);
```

While Firebase Security Rules validate data types and lengths, the client code does NOT validate input before sending. Specifically:

- **No Civil ID format validation** — accepts any string ≤20 chars
- **No name character validation** — could contain control characters
- **No ward format validation** — app expects patterns like "W14R3" but accepts anything
- **Triage code validation only on UI selection** — API can receive any value

**Firebase rules DO enforce** `code >= 1 && code <= 4` and field types, providing a safety net. But client-side validation is missing, meaning users see confusing Firebase rejection errors rather than friendly validation messages.

**Severity:** MEDIUM
**Fix:** Add client-side validation mirroring Firebase rules, with clear error messages.

---

## 3. Firebase Security Rules — Detailed Exploitation Scenarios

### 3.1 Rules Analysis

**File:** `database.rules.json`

```
patients/$unit/$patient  → auth != null (read/write)
pins/$pin               → auth != null (read/write)
config                  → auth != null (read) / false (write)
audit/$entry            → false (read) / auth != null (write)
$other                  → false (read/write)
```

### 3.2 Exploitation Scenario: Mass Patient Data Exfiltration

```
Step 1: Open browser DevTools on any device with the app
Step 2: Firebase anonymous auth happens automatically on page load
Step 3: Execute in console:
        firebase.database().ref('patients').once('value')
          .then(s => console.log(JSON.stringify(s.val())))
Step 4: All patient data across ALL units is now in the console
Step 5: Export to file
```

**Time Required:** Under 30 seconds
**Authentication Required:** None (anonymous auth is automatic)
**Detection:** Audit log does NOT capture bulk reads — only writes are logged

### 3.3 Exploitation Scenario: PIN Harvesting

```
Step 1: firebase.database().ref('pins').once('value')
          .then(s => console.log(s.val()))
Step 2: All PIN hashes (or plaintext defaults) are exposed
Step 3: For 4-digit PINs, brute-force the hash: only 10,000 possibilities
Step 4: SHA-256 with known salt + 10k candidates = instant crack
```

**Time Required:** Under 5 seconds for plaintext PINs; ~1 second for hash cracking

### 3.4 Exploitation Scenario: Data Manipulation

```
Step 1: Authenticate anonymously (automatic)
Step 2: firebase.database().ref('patients/A_M').push({
          name: "Injected Patient",
          civil: "000000000000",
          ward: "X99",
          code: 4,
          ts: Date.now()
        })
Step 3: Phantom critical patient appears in Unit A Male
Step 4: Hospital staff may allocate resources to non-existent patient
```

**Clinical Impact:** Triage manipulation could divert resources during emergencies.

### 3.5 Exploitation Scenario: Mass Deletion

```
firebase.database().ref('patients').remove()
// Deletes ALL patient records across ALL units
```

**Mitigation:** Offline cache would preserve data on devices that were online at time of deletion. But new devices connecting post-deletion would see empty wards.

### 3.6 Rule Gaps Summary

| Gap | Issue | Fix |
|-----|-------|-----|
| No per-unit access control | Any auth user can read/write ALL units | Add unit-specific tokens via Custom Claims |
| PINs readable | PIN hashes exposed to all users | Move validation to Cloud Function; set `.read: false` |
| No write rate limiting | Attacker can flood DB with records | Add Firebase App Check + rate limiting Cloud Function |
| No read auditing | Bulk data reads are invisible | Use Cloud Functions for data access logging |
| No IP/device restrictions | Any device worldwide can access | Add Firebase App Check for device attestation |

---

## 4. Service Worker & Caching — Attack Surface Analysis

### 4.1 Service Worker Review

**File:** `sw.js` (65 lines)

**Architecture:**
```
Install → Precache 7 assets → skipWaiting (immediate activation)
Activate → Delete old caches → clients.claim (take control immediately)
Fetch → Route by type:
  - Firebase/Gemini API: passthrough (no cache)
  - HTML/navigation: network-first, cache fallback
  - Other assets: cache-first, network fallback
```

### 4.2 Finding: Firebase Auth SDK Not Precached (NEW — MEDIUM)

**Location:** `sw.js:3-12`

```javascript
const PRECACHE = [
  "/",
  "/index.html",
  "/manifest.json",
  "/icon-192.png",
  "/icon-512.png",
  "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js",
  "https://www.gstatic.com/firebasejs/10.12.0/firebase-database.js",
  "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap"
];
```

**Missing from precache:**
- `firebase-auth.js` — Auth SDK loaded by `index.html:265` but NOT precached
- Actual font files served by Google Fonts (only the CSS is cached, not the WOFF2 files)

**Impact:** On a true cold-start offline scenario:
1. `index.html` loads from cache ✓
2. `firebase-app.js` loads from cache ✓
3. `firebase-database.js` loads from cache ✓
4. `firebase-auth.js` → **FAILS** → console error, but app may still function with cached data
5. Font files → **FAILS** → text renders in system fallback font

**Severity:** MEDIUM (functional degradation, not failure)
**Fix:** Add `firebase-auth.js` to `PRECACHE` array:
```javascript
"https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js",
```

### 4.3 Finding: skipWaiting Creates Update Race Condition (LOW)

**Location:** `sw.js:20-21`

```javascript
self.skipWaiting();
```

Combined with `index.html:583-593`:
```javascript
navigator.serviceWorker.getRegistrations()
  .then(rs => Promise.all(rs.map(r => r.unregister())))
  .then(() => {
    navigator.serviceWorker.register("/sw.js", {updateViaCache: "none"})
      .then(r => r.update())
  })
```

**Issue:** On every page load, ALL existing service workers are unregistered, then a new one is registered. This aggressive approach:
- Forces a re-download and re-cache on every visit
- Creates a brief window where no SW is active (requests are uncached)
- During that window, if network fails, the app gets no cache benefits

**Severity:** LOW (only affects the brief re-registration window)
**Fix:** Use standard SW update flow instead of unregister-all:
```javascript
navigator.serviceWorker.register("/sw.js", {updateViaCache: "none"})
  .then(r => r.update());
```

### 4.4 Finding: No Cache Size Management (LOW)

The cache stores all fetched assets indefinitely without eviction. Over time, the `mak-v10` cache will grow as new font files, SDK patches, etc., are fetched.

**Impact:** Could exhaust storage quota on low-storage devices.
**Severity:** LOW

---

## 5. iOS Native Wrapper — Full Security Review

### 5.1 Overall Assessment: STRONG

The iOS wrapper (`ViewController.swift`, 194 lines) is well-implemented with defense-in-depth.

### 5.2 Domain Allowlisting — PASS

**Location:** `ViewController.swift:154-166`

```swift
private static let allowedDomains = [
    "unit-e-1d07b.web.app",
    "unit-e-1d07b.firebaseapp.com",
    "unit-e-1d07b-default-rtdb.europe-west1.firebasedatabase.app",
    "firebaseio.com", "googleapis.com", "gstatic.com",
    "identitytoolkit.googleapis.com", "securetoken.googleapis.com",
    "generativelanguage.googleapis.com",
    "fonts.googleapis.com", "fonts.gstatic.com"
]
```

**Verification:** The `isAllowedHost()` function uses suffix matching:
```swift
host == domain || host.hasSuffix("." + domain)
```

This is secure — it prevents subdomain spoofing (e.g., `evil-gstatic.com` would NOT match `gstatic.com`).

### 5.3 App Transport Security — PASS

**Location:** `Info.plist:51-113`

```xml
<key>NSAllowsArbitraryLoads</key>
<false/>
<key>NSAllowsArbitraryLoadsInWebContent</key>
<false/>
```

All domains require:
- TLS 1.2 minimum
- Forward secrecy enabled
- No arbitrary loads permitted

### 5.4 ATS Discrepancy Between Info.plist and project.yml (NEW — MEDIUM)

**Finding:** There is a **conflict** between the two configuration files:

`Info.plist:55`: `NSAllowsArbitraryLoadsInWebContent` = **false**
`project.yml:39`: `NSAllowsArbitraryLoadsInWebContent` = **true**

**Location:** `project.yml:37-39`

```yaml
NSAppTransportSecurity:
  NSAllowsArbitraryLoads: false
  NSAllowsArbitraryLoadsInWebContent: true    # ← ALLOWS arbitrary web loads!
```

**Impact:** XcodeGen uses `project.yml` to GENERATE `Info.plist`. The checked-in `Info.plist` says `false`, but the build-time generated `Info.plist` says `true`. The **build pipeline uses XcodeGen**, so the actual IPA ships with arbitrary web content loads ENABLED.

This means the WKWebView can load content from ANY domain over ANY protocol, bypassing the carefully constructed allowlist in `ViewController.swift`.

**Severity:** MEDIUM
**Fix:** Change `project.yml:39` to `false`:
```yaml
NSAllowsArbitraryLoadsInWebContent: false
```

### 5.5 JavaScript Injection from Native Side (LOW)

**Location:** `ViewController.swift:120-123`

```swift
private func injectOfflineStatus(_ offline: Bool) {
    isOffline = offline
    let js = "if(typeof S!=='undefined'){S.online=\(offline ? "false" : "true");if(typeof render==='function')render();}"
    webView.evaluateJavaScript(js, completionHandler: nil)
}
```

**Assessment:** The injected JavaScript uses only boolean literals (`true`/`false`), so no injection risk. **PASS.**

### 5.6 Missing WKWebView Security Configurations (NEW — LOW)

| Configuration | Current | Recommended | Risk |
|--------------|---------|-------------|------|
| `javaScriptCanOpenWindowsAutomatically` | `false` | `false` | PASS |
| `allowsContentJavaScript` | `true` | `true` | Required |
| `allowsBackForwardNavigationGestures` | `false` | `false` | PASS |
| `limitsNavigationsToAppBoundDomains` | Not set | `true` | Would strengthen domain restriction |
| `requiresUserActionForMediaPlayback` | Not set | `true` | LOW risk |

### 5.7 Bundle ID and Signing Configuration

**Location:** `project.yml:56-64`

```yaml
PRODUCT_BUNDLE_IDENTIFIER: com.medevac.app
DEVELOPMENT_TEAM: YPGU5K4U57
CODE_SIGN_STYLE: Manual
CODE_SIGN_IDENTITY: "Apple Distribution"
```

**Assessment:**
- Bundle ID: `com.medevac.app` — properly namespaced
- Development team hardcoded (should match Codemagic/GitHub secrets)
- Manual code signing: correct for CI/CD environments
- App category: `public.app-category.medical` — correct classification

---

## 6. Android TWA — Build Pipeline & Runtime Security

### 6.1 Hardcoded Fallback Keystore Password (CRITICAL)

**Location:** `codemagic.yaml:36-37`

```yaml
-storepass "${CM_KEYSTORE_PASSWORD:-medevac123}" \
-keypass "${CM_KEYSTORE_PASSWORD:-medevac123}" \
```

And `codemagic.yaml:99-101`:
```groovy
storePassword System.getenv("CM_KEYSTORE_PASSWORD") ?: "medevac123"
keyAlias "medevac"
keyPassword System.getenv("CM_KEYSTORE_PASSWORD") ?: "medevac123"
```

**Vulnerability:** If `CM_KEYSTORE_PASSWORD` environment variable is not set, the build falls back to the plaintext password `"medevac123"`, which is committed to the public repository.

**Impact:**
- Anyone can sign APKs with the same identity
- Enables man-in-the-middle APK replacement attacks
- Violates Google Play signing requirements

**Severity:** CRITICAL
**Fix:** Remove the fallback password. If the env var is missing, the build should FAIL, not proceed with a known password:
```yaml
-storepass "${CM_KEYSTORE_PASSWORD}" \
```

### 6.2 New Keystore Generated on Every Build (HIGH)

**Location:** `build-apk.yml:67-77` and `codemagic.yaml:29-38`

```yaml
- name: Generate signing keystore
  run: |
    keytool -genkeypair \
      -alias medevac \
      -keyalg RSA -keysize 2048 \
      -validity 10000 \
      -keystore keystore.jks \
      ...
```

**Issue:** A NEW keystore is generated on every CI build. This means:
- Each APK is signed with a DIFFERENT key
- Users cannot update from one build to the next (signature mismatch)
- Android rejects updates with mismatched signatures
- Google Play will reject uploads with varying signatures

**Severity:** HIGH
**Fix:** Store a persistent keystore in GitHub Secrets / Codemagic environment:
```yaml
echo "$KEYSTORE_BASE64" | base64 --decode > keystore.jks
```

### 6.3 Android TWA Launches Chrome Custom Tab, Not TWA (MEDIUM)

**Location:** `codemagic.yaml:176-189`

```java
public class LauncherActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        CustomTabsIntent customTabsIntent = new CustomTabsIntent.Builder()
            .setShareState(CustomTabsIntent.SHARE_STATE_OFF)
            .build();
        customTabsIntent.intent.setPackage("com.android.chrome");
        customTabsIntent.launchUrl(this, Uri.parse(URL));
        finish();
    }
}
```

**Issue:** This is NOT a Trusted Web Activity. It launches a Chrome Custom Tab, which:
- Shows a Chrome address bar (not full-screen)
- Does NOT have access to Service Worker registrations from the app context
- Does NOT support PWA features like `display: standalone`
- Depends on `com.android.chrome` being installed (not all devices have this package name)

**The GitHub Actions pipeline** uses Bubblewrap, which DOES create a proper TWA. But the **Codemagic pipeline** creates a Custom Tabs launcher, which is inferior.

**Severity:** MEDIUM
**Fix:** Replace `CustomTabsIntent` with `TrustedWebActivityIntentBuilder` in the Codemagic build.

### 6.4 Android `allowBackup="true"` (MEDIUM)

**Location:** `codemagic.yaml` (AndroidManifest.xml):

```xml
<application
    android:allowBackup="true"
    ...>
```

**Impact:** Android backup allows extraction of app data (including cached patient records) via `adb backup`. An attacker with physical access or a compromised backup can extract all locally stored data.

**Fix:** Set `android:allowBackup="false"` for healthcare applications.

---

## 7. CI/CD Pipeline Security Audit

### 7.1 GitHub Actions Workflows

#### 7.1.1 deploy-web.yml — PASS (mostly)

```yaml
- uses: FirebaseExtended/action-hosting-deploy@v0
  with:
    repoToken: ${{ secrets.GITHUB_TOKEN }}
    firebaseServiceAccount: ${{ secrets.FIREBASE_SERVICE_ACCOUNT }}
    channelId: live
    projectId: ${{ secrets.FIREBASE_PROJECT_ID }}
    entryPoint: ./MAK_Registry
```

**Assessment:**
- Secrets properly referenced, not hardcoded ✓
- Deploys only from `main` branch ✓
- Uses official Firebase action ✓

**Issue:** `channelId: live` means every push to `main` deploys directly to production. No staging environment, no smoke tests, no approval gate.

**Severity:** MEDIUM
**Fix:** Add a staging channel + manual approval for production.

### 7.1.2 build-ios.yml — PASS with Notes

**Good practices:**
- Conditional signing (only if secrets are configured) ✓
- Keychain cleanup in `always()` block ✓
- Separate simulator vs. device builds ✓

**Issue:** `HAS_SIGNING` check at line 41-43 has a syntax error:

```yaml
if: ${{ env.HAS_SIGNING == 'true' }}
env:
  HAS_SIGNING: ${{ secrets.APPLE_CERTIFICATE_BASE64 != '' }}
```

The `env` block is defined INSIDE the step, but `HAS_SIGNING` is set to the result of a comparison. GitHub Actions evaluates `secrets.APPLE_CERTIFICATE_BASE64 != ''` as a boolean string. This works but is fragile.

### 7.1.3 Hosting Configuration — Public Directory Exposure

**Location:** `firebase.json:7`

```json
"public": ".",
```

The ENTIRE `MAK_Registry/` directory is the hosting root. The `ignore` patterns exclude only:
```json
"ignore": ["firebase.json", "**/.*", "database.rules.json"]
```

**Missing from ignore:** `database.rules.json` IS excluded, but `sw.js`, all HTML files, all images are served. This is expected behavior, but note that `privacy.html` and `support.html` are publicly accessible without authentication.

### 7.2 Codemagic Pipeline

#### 7.2.1 Exposed Credentials Configuration

**Location:** `codemagic.yaml:213-217`

```yaml
vars:
  BUNDLE_ID: com.medevac.app
  APP_STORE_CONNECT_KEY_ID: 346WF7MN3Z
  APP_STORE_CONNECT_ISSUER_ID: 5988b726-9289-48c6-ac37-4c603d29fa6a
```

**Issue:** App Store Connect API Key ID and Issuer ID are committed to source. While these alone are not sufficient to authenticate (the private key is in a secret group), they reduce the attacker's search space and should be treated as sensitive.

**Severity:** LOW
**Fix:** Move to Codemagic secret groups.

#### 7.2.2 Developer Email Exposed

**Location:** `codemagic.yaml:331-332`

```yaml
recipients:
  - b.alhaddad13@gmail.com
```

**Impact:** Developer's personal email is committed to public source control. Could be targeted for phishing.

**Severity:** LOW

---

## 8. Privacy Policy & Legal Compliance Gap Analysis

### 8.1 Privacy Policy Review

**File:** `privacy.html` (bilingual Arabic/English)

| Requirement | Present | Adequate | Gap |
|------------|---------|----------|-----|
| Data types collected | ✓ | ✓ | — |
| Purpose of collection | ✓ | ✓ | — |
| Data storage location | ✓ | PARTIAL | Does not specify EU region or Google Cloud specifics |
| Third-party services | ✓ | PARTIAL | Lists Firebase & Gemini but not Google Fonts (tracking concern) |
| Data sharing policy | ✓ | ✓ | — |
| Security measures | ✓ | MISLEADING | Claims "PIN-based authentication" without disclosing weaknesses |
| Data retention period | ✗ | — | No retention policy stated |
| Breach notification | ✗ | — | No breach notification procedure |
| Data processing agreement | ✗ | — | No DPA reference |
| Cookie/localStorage disclosure | ✗ | — | Uses localStorage but not disclosed |
| User consent mechanism | ✗ | — | No consent capture before data collection |
| Right to deletion | ✓ | PARTIAL | Only via email request to admin |
| Right to data portability | ✗ | — | No export mechanism for individual patients |
| Children's data (if applicable) | ✗ | — | No age restriction stated |
| International data transfer | ✗ | — | Data transfers to Google US/EU not disclosed |
| Contact for DPO | ✗ | — | No Data Protection Officer designated |

### 8.2 Support Page Review

**File:** `support.html`

**Issue:** FAQ answer about offline capability is misleading:

```
"Previously loaded data can be viewed offline, but adding or editing
requires an internet connection for sync."
```

**Reality:** The app DOES support offline add/edit (queued to sync). The support page contradicts the actual functionality. This could cause staff to avoid using the app during network outages.

**Severity:** MEDIUM (operational impact during emergencies)
**Fix:** Update support page to accurately describe offline capabilities.

---

## 9. Operational Readiness Assessment

### 9.1 Disaster Recovery

| Scenario | Recovery Plan | Status |
|----------|--------------|--------|
| Firebase database corruption | No backup/restore procedure | FAIL |
| Firebase outage > 24 hours | Offline cache only; no alternative backend | PARTIAL |
| Device loss/theft | No remote wipe capability | FAIL |
| Admin PIN forgotten | Hardcoded default still works | INSECURE |
| Mass casualty > 500 patients | No tested scale | UNKNOWN |
| Power outage | PWA works on battery devices | PASS |
| Internet outage | Full offline CRUD with queue | PASS |

### 9.2 Training & Documentation

| Document | Exists | Quality |
|----------|--------|---------|
| User manual | No | N/A |
| Admin guide | No | N/A |
| Deployment guide | No | N/A |
| Incident response plan | No | N/A |
| FAQ page | Yes | Partially inaccurate |
| Privacy policy | Yes | Incomplete |
| Training materials | No | N/A |

### 9.3 Monitoring & Alerting

| Capability | Status |
|-----------|--------|
| Uptime monitoring | None |
| Error tracking (Sentry, etc.) | None |
| Performance monitoring | None |
| Security event alerting | None |
| Audit log review dashboard | None |
| Firebase usage monitoring | Firebase Console only |
| Automated health checks | None |

---

## 10. Performance & Scalability Analysis

### 10.1 Client-Side Rendering Performance

The application re-renders the entire DOM on every state change via `render()`:

```javascript
function render() {
  let h = "";
  if (s === "home") h = vHome();
  else if (s === "ward") h = vWard();
  ...
  app.innerHTML = h;    // Full DOM replacement
  bindAll();            // Re-attach ALL event listeners
}
```

**Analysis:**
- `innerHTML` assignment destroys and recreates the entire DOM tree
- `bindAll()` uses `querySelectorAll` to re-attach every event listener
- For a ward with N patients, render complexity is O(N) string concatenation + O(N) DOM operations + O(N) event bindings

**Projected Performance:**

| Patient Count | Render Time (est.) | User Experience |
|--------------|-------------------|-----------------|
| 10 | <50ms | Smooth |
| 50 | ~100ms | Acceptable |
| 200 | ~400ms | Noticeable lag |
| 500 | ~1s | Janky, dropped frames |
| 1000+ | >2s | Unusable |

**Severity:** MEDIUM (for MCI scenarios with high patient counts)
**Fix:** Use virtual DOM diffing or manual DOM updates instead of full `innerHTML` replacement.

### 10.2 Firebase Realtime Database Scaling

```javascript
onValue(ref(db, "patients/" + uid), snap => {
  const raw = snap.val() || {};
  S.patients = Object.entries(raw).map(([k,v]) => ({...v, _k:k}));
  ...
});
```

**Issue:** `onValue` downloads the ENTIRE unit's patient list on every change. If any patient in the unit is modified, ALL patients are re-downloaded.

**Impact:**
- For 500 patients × ~200 bytes each = ~100KB per change event
- Multiple concurrent editors would trigger cascading full refreshes
- Mobile data usage could be significant during MCI

**Fix:** Use `onChildAdded`, `onChildChanged`, `onChildRemoved` for incremental updates.

### 10.3 localStorage Scaling

| Metric | Limit | Current Usage Pattern |
|--------|-------|----------------------|
| localStorage quota | ~5-10MB | Stores all patients + queue + PIN cache |
| Patient record size | ~200 bytes | Name + civil + ward + code + notes |
| Max patients (5MB) | ~25,000 | Sufficient for single hospital |
| Max patients (10MB) | ~50,000 | Sufficient |

**Assessment:** localStorage quotas are adequate for expected hospital census volumes. **PASS.**

---

## 11. Error Handling & Resilience Audit

### 11.1 Error Handling Coverage

| Operation | Error Handler | User Feedback | Recovery |
|-----------|--------------|---------------|----------|
| Firebase read failure | `onValue` implicit | None | Falls back to cache |
| Firebase write failure | `catch` block | "Saved offline" toast | Queues for sync |
| Firebase auth failure | `catch` → console.warn | None | App continues without auth |
| Gemini OCR failure | `catch` → toast | "OCR failed" toast | User can retry |
| Service Worker install fail | `catch` → console.warn | None | App works without SW |
| Network loss | `offline` event | "Offline" banner | Full offline mode |
| PIN validation failure | Error message render | "Wrong PIN" message | User retries |
| Seed data failure | `catch` → console.warn | None | Continues without seed |

### 11.2 Unhandled Failure Modes

| Scenario | Current Behavior | Risk |
|----------|-----------------|------|
| localStorage full | Silent failure (`try/catch` returns silently) | Data loss |
| Corrupt localStorage data | `_dec()` returns null → JSON.parse fails → caught | App boots with empty data |
| Firebase SDK fails to load (CDN down + no SW cache) | Script error → blank page | App unusable |
| WebSocket disconnect during real-time sync | Firebase SDK auto-reconnects | Temporary stale data |
| Multiple tabs editing same patient | Last-write-wins | Data overwritten silently |
| Browser clears site data | All offline data lost | User sees empty app |

### 11.3 Critical Blind Spot: Silent Auth Failure

**Location:** `index.html:271`

```javascript
signInAnonymously(auth).catch(e => console.warn("Auth failed", e));
```

If anonymous auth fails (e.g., Firebase Auth service down), the app continues but ALL Firebase reads/writes will fail silently. The user sees cached data and may not realize their changes are not being saved even when online.

**Fix:** Show a visible "Connection error" indicator when auth fails, not just a console warning.

---

## 12. State Management & Data Consistency

### 12.1 Global State Object

**Location:** `index.html:382`

```javascript
let S = {
  screen: "home", unit: null, patients: [], allData: {},
  pins: {...PINS}, filter: "all", search: "", online: navigator.onLine,
  editP: null, editCode: null, addCode: null, pinTarget: null,
  pinVal: "", pinError: false, ocrImg: null, ocrB64: null,
  ocrResults: [], ocrSel: [], ocrLoading: false, adminTab: "overview",
  showCivil: {}, _bp: false
};
```

**Issues:**
1. **Single mutable global** — No state isolation between UI concerns
2. **PIN stored in memory** — `S.pinVal` holds entered PIN digits in memory
3. **Patient data in memory** — `S.patients` and `S.allData` hold all PHI in JS heap
4. **No state serialization protection** — DevTools can read `window.S` directly

### 12.2 Data Consistency Gaps

| Scenario | Consistency Risk |
|----------|-----------------|
| User edits patient, goes offline, another user edits same patient | Last-write-wins on reconnect; first user's offline changes overwrite second user's online changes |
| User adds patient offline, admin deletes unit while offline | Offline queue pushes to deleted unit path — Firebase recreates it |
| Cache has stale data, user views then goes offline | User makes decisions based on outdated patient status |
| Two devices both add patients offline with auto-generated offline keys | No key collision (keys use timestamps), but duplicate patients possible |

### 12.3 Memory Leak Potential

**Location:** `index.html:398`

```javascript
onValue(ref(db, "patients/" + uid), snap => { ... });
```

Firebase `onValue` listeners are attached but only detached when switching units:
```javascript
function listenUnit(uid) {
  if (S.unit) off(ref(db, "patients/" + S.unit));
  ...
}
```

The `listenAll()` listener for the admin view is NEVER detached:
```javascript
let _listenAllDone = false;
function listenAll() {
  if (_listenAllDone) return;
  _listenAllDone = true;
  onValue(ref(db, "patients"), ...);
  onValue(ref(db, "pins"), ...);
}
```

**Impact:** Once an admin session is opened, the `patients` and `pins` listeners remain active for the entire session, receiving updates for ALL data even after navigating away from admin.

**Severity:** LOW (functional, but wastes bandwidth)

---

## 13. New Findings Register

### Combined with Volume I Findings

| ID | Finding | Severity | Category | Volume |
|----|---------|----------|----------|--------|
| C-1 | Hardcoded default PINs in client JavaScript | CRITICAL | Security | I |
| C-2 | XOR offline encryption is not cryptographic | CRITICAL | Data Protection | I |
| C-3 | No per-user authentication / RBAC | CRITICAL | Access Control | I |
| **V-01** | **XSS via error handler innerHTML injection** | **CRITICAL** | **Security** | **II** |
| **V-03** | **PIN plaintext fallback enables offline bypass** | **CRITICAL** | **Security** | **II** |
| **V-08** | **Hardcoded fallback keystore password `medevac123`** | **CRITICAL** | **Build Security** | **II** |
| C-4 | No PIN brute-force rate limiting | HIGH | Security | I |
| C-5 | Firebase anonymous auth, no user identity | HIGH | Security | I |
| C-6 | Hardcoded salt for PIN hashing | HIGH | Cryptography | I |
| C-7 | No automated test suite | HIGH | Quality | I |
| C-8 | No HIPAA/Kuwait compliance framework | HIGH | Regulatory | I |
| **V-06** | **Seed data with real-looking patient records in source** | **HIGH** | **Privacy** | **II** |
| **V-09** | **New Android keystore generated per build** | **HIGH** | **Build** | **II** |
| C-9 | `unsafe-inline` in CSP | MEDIUM | Security | I |
| C-10 | No data retention / purge policy | MEDIUM | Data Governance | I |
| **V-02** | **DOM XSS possible in confirm dialog** | **MEDIUM** | **Security** | **II** |
| **V-04** | **Gemini API key readable by any client** | **MEDIUM** | **Secrets** | **II** |
| **V-05** | **Cross-domain localStorage key mismatch** | **MEDIUM** | **Data** | **II** |
| **V-07** | **No client-side input validation** | **MEDIUM** | **Data Integrity** | **II** |
| **V-10** | **ATS discrepancy: project.yml allows arbitrary web loads** | **MEDIUM** | **iOS Security** | **II** |
| **V-11** | **Firebase Auth SDK not precached in SW** | **MEDIUM** | **Offline** | **II** |
| **V-12** | **Support page contradicts offline capability** | **MEDIUM** | **Operational** | **II** |
| **V-13** | **No staging environment; pushes deploy directly to prod** | **MEDIUM** | **DevOps** | **II** |
| **V-14** | **Android allowBackup=true exposes data via ADB** | **MEDIUM** | **Android** | **II** |
| **V-15** | **Silent auth failure with no user notification** | **MEDIUM** | **Resilience** | **II** |

### Totals

| Severity | Volume I | Volume II (New) | Combined |
|----------|----------|-----------------|----------|
| CRITICAL | 3 | 3 | **6** |
| HIGH | 5 | 2 | **7** |
| MEDIUM | 2 | 9 | **11** |
| LOW | 0 | 4 (noted inline) | **4** |
| **Total** | **10** | **14** | **28** |

---

## 14. Combined Risk Heat Map

```
            │ LOW Impact  │ MED Impact  │ HIGH Impact │ CRIT Impact │
────────────┼─────────────┼─────────────┼─────────────┼─────────────┤
HIGH        │             │ V-07, V-12  │ C-4, C-6    │ C-1, V-03   │
Likelihood  │             │ V-13        │ V-06        │ C-2, C-3    │
            │             │             │             │ V-01, V-08  │
────────────┼─────────────┼─────────────┼─────────────┼─────────────┤
MEDIUM      │ V-05        │ V-04, V-11  │ C-7, C-8    │             │
Likelihood  │             │ V-14, V-15  │ V-09        │             │
────────────┼─────────────┼─────────────┼─────────────┼─────────────┤
LOW         │ SW race     │ C-9, C-10   │             │             │
Likelihood  │ Cache size  │ V-02, V-10  │             │             │
────────────┴─────────────┴─────────────┴─────────────┴─────────────┘
```

---

## 15. Detailed Remediation Specifications

### 15.1 Priority 0 — Immediate (Block Deployment)

#### Fix V-01: XSS in Error Handlers

```javascript
// BEFORE (vulnerable):
window.onerror = function(m,s,l,c,e) {
  showFatal('<div>...' + m + '</div>');
};

// AFTER (safe):
window.onerror = function(m,s,l,c,e) {
  const div = document.createElement('div');
  div.style.cssText = 'padding:40px;color:red;font-size:13px;word-break:break-all';
  div.textContent = 'Error: ' + m + ' (Line: ' + l + ')';
  document.getElementById("app")?.replaceChildren(div);
};
```

#### Fix V-03: Remove PIN Plaintext Fallback

```javascript
// BEFORE:
const stored = S.pins[S.pinTarget] || PINS[S.pinTarget];

// AFTER:
const stored = S.pins[S.pinTarget];
if (!stored) { toast("PIN not loaded. Check connection.", "err"); return; }
```

#### Fix V-08: Remove Keystore Password Fallback

```yaml
# BEFORE:
-storepass "${CM_KEYSTORE_PASSWORD:-medevac123}"

# AFTER:
-storepass "${CM_KEYSTORE_PASSWORD:?KEYSTORE PASSWORD NOT SET}"
```

### 15.2 Priority 1 — Within 1 Week

| Fix | Specification |
|-----|--------------|
| V-06: Remove seed data | Delete `SEED_M`, `SEED_F` arrays and `seedData()` function |
| V-09: Persistent keystore | Store keystore as base64 in CI secrets; decode at build time |
| V-10: Fix ATS in project.yml | Set `NSAllowsArbitraryLoadsInWebContent: false` |
| V-11: Precache Auth SDK | Add `firebase-auth.js` URL to `PRECACHE` array in `sw.js` |
| V-12: Fix support page | Update offline FAQ to reflect actual offline add/edit capability |
| V-14: Disable Android backup | Set `android:allowBackup="false"` in AndroidManifest |
| V-15: Show auth failure | Replace console.warn with visible UI indicator on auth failure |

### 15.3 Priority 2 — Within 1 Month

| Fix | Specification |
|-----|--------------|
| V-02: Safe confirm dialog | Apply `esc()` to title and msg inside `confirm2()` |
| V-04: Proxy Gemini API | Create Cloud Function to proxy OCR requests; remove key from client |
| V-05: Normalize cache key | Use fixed key prefix or normalize hostname |
| V-07: Client validation | Add Civil ID format regex, name character validation, ward format check |
| V-13: Add staging env | Create `staging` Firebase hosting channel; require manual approval for `live` |

---

## Appendix A: Audit Trail Sample

The audit function logs the following events:

```javascript
audit(action, unit, detail)
// Writes to: /audit/{pushKey}
// Fields: action, unit, detail, ts, uid, ua
```

| Event | Logged | Action Value |
|-------|--------|-------------|
| PIN authentication success | Yes | `"login"` |
| PIN authentication failure | **No** | — |
| Patient created | Yes | `"add"` |
| Patient edited | Yes | `"edit"` |
| Patient deleted | Yes | `"delete"` |
| OCR import | Yes | `"ocr_import"` |
| PIN changed | Yes | `"pin_change"` |
| Data viewed/read | **No** | — |
| Civil ID unmasked | **No** | — |
| Backup PNG exported | **No** | — |
| Admin panel accessed | **No** | — |
| Session timeout | **No** | — |

**Critical Gap:** Failed login attempts are not logged, making brute-force attacks invisible.

---

## Appendix B: Complete Secrets Inventory

| Secret | Location | Exposure |
|--------|----------|----------|
| Firebase API Key | `index.html:266` (hardcoded) | Public — by design |
| Gemini API Key | Firebase `/config/geminiKey` | Readable by any auth client |
| Default PINs (all 11) | `index.html:326` (hardcoded) | Public in source code |
| PIN salt | `index.html:410` (hardcoded) | Public in source code |
| Keystore password fallback | `codemagic.yaml:36` (hardcoded) | Public in source code |
| Apple Team ID | `project.yml:59` (hardcoded) | Public in source code |
| ASC Key ID | `codemagic.yaml:216` (hardcoded) | Public in source code |
| ASC Issuer ID | `codemagic.yaml:217` (hardcoded) | Public in source code |
| Developer email | `codemagic.yaml:332`, `privacy.html:75` | Public in source code |
| Firebase project ID | `index.html:266` (hardcoded) | Public — by design |

---

*End of Volume II. This report should be read in conjunction with Volume I (EMERGENCY_HOSPITAL_AUDIT.md) for the complete audit picture.*

*Total findings across both volumes: 28 (6 Critical, 7 High, 11 Medium, 4 Low)*
