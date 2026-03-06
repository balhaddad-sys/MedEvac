# MedEvac Emergency Hospital Audit Report — Volume III

**System:** MedEvac — Secure Patient Registry System
**Facility:** Mubarak Al-Kabeer Hospital, Kuwait
**Audit Date:** 2026-03-06
**Audit Type:** Threat Modeling, Clinical Safety, Usability & Operational Audit
**Predecessors:** Vol. I (Structural), Vol. II (Code-Level Technical)
**Classification:** CONFIDENTIAL — For Authorized Hospital Administration Only

---

## Table of Contents

1. [STRIDE Threat Model](#1-stride-threat-model)
2. [Attack Tree Analysis](#2-attack-tree-analysis)
3. [Clinical Safety — Failure Mode & Effects Analysis (FMEA)](#3-clinical-safety--failure-mode--effects-analysis-fmea)
4. [Usability Heuristic Evaluation](#4-usability-heuristic-evaluation)
5. [Logic & Race Condition Audit](#5-logic--race-condition-audit)
6. [PWA Manifest & Install Audit](#6-pwa-manifest--install-audit)
7. [Database Rules — Edge Case Analysis](#7-database-rules--edge-case-analysis)
8. [iOS Icon & App Store Compliance](#8-ios-icon--app-store-compliance)
9. [Triage Protocol Alignment](#9-triage-protocol-alignment)
10. [Backup PNG — Data Leakage Analysis](#10-backup-png--data-leakage-analysis)
11. [Session & Timeout Behavior Analysis](#11-session--timeout-behavior-analysis)
12. [Offline Queue — Integrity & Ordering Guarantees](#12-offline-queue--integrity--ordering-guarantees)
13. [Social Engineering & Physical Security](#13-social-engineering--physical-security)
14. [Findings Volume III](#14-findings-volume-iii)
15. [Master Findings Table — All Three Volumes](#15-master-findings-table--all-three-volumes)
16. [Executive Remediation Priority Matrix](#16-executive-remediation-priority-matrix)

---

## 1. STRIDE Threat Model

STRIDE is a structured threat modeling framework: **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege.

### 1.1 Asset Inventory

| Asset | Value | Location |
|-------|-------|----------|
| Patient PHI (name, civil ID, triage code) | CRITICAL | Firebase DB + localStorage |
| Triage classifications (life-critical) | CRITICAL | Firebase DB |
| Admin PIN / Unit PINs | HIGH | Firebase `pins` node |
| Gemini API key | MEDIUM | Firebase `config` node |
| Audit trail | HIGH | Firebase `audit` node |
| App source code | MEDIUM | GitHub (public) |
| Signing keystore | HIGH | CI secrets |

### 1.2 STRIDE Analysis per Asset

#### Patient PHI

| Threat | Scenario | Likelihood | Impact | Mitigation Exists? |
|--------|----------|-----------|--------|--------------------|
| **S**poofing | Attacker authenticates as legitimate user | HIGH | HIGH | NO — anonymous auth only |
| **T**ampering | Attacker modifies triage code via Firebase API | HIGH | CRITICAL | PARTIAL — Firebase rules validate type, not actor |
| **R**epudiation | Nurse denies editing a patient; no named audit | HIGH | HIGH | NO — audit logs only anonymous UID |
| **I**nformation Disclosure | Bulk export via Firebase REST API | HIGH | CRITICAL | NO — any auth client can read all |
| **D**enial of Service | `remove()` all patient records | MEDIUM | CRITICAL | NO — no delete protection |
| **E**levation of Privilege | Any user accessing any unit by reading PINs | HIGH | CRITICAL | NO — PINs are readable |

#### Triage Classifications

| Threat | Scenario | Likelihood | Impact | Mitigation Exists? |
|--------|----------|-----------|--------|--------------------|
| **T**ampering | Downgrade critical patient to Green | HIGH | CRITICAL | NO |
| **T**ampering | Mark all patients Critical (panic) | HIGH | HIGH | NO |
| **R**epudiation | Who changed triage code? | HIGH | HIGH | PARTIAL — action logged, not actor |
| **I**nformation Disclosure | Competitor hospital or insurer reads codes | LOW | HIGH | NO |

#### Admin PIN

| Threat | Scenario | Likelihood | Impact | Mitigation Exists? |
|--------|----------|-----------|--------|--------------------|
| **S**poofing | Brute-force 4-digit PIN (10,000 combos) | HIGH | CRITICAL | NO — no rate limit |
| **I**nformation Disclosure | Read PIN hashes from Firebase | HIGH | HIGH | NO |
| **I**nformation Disclosure | Read default PINs from source code | CERTAIN | CRITICAL | NO |
| **E**levation of Privilege | Unit nurse reads ADMIN PIN; gains admin access | HIGH | CRITICAL | NO |

### 1.3 Highest Priority STRIDE Threats

```
CRITICAL RISK ZONE (High Likelihood × Critical Impact):
┌─────────────────────────────────────────────────────────────┐
│ 1. Patient triage tampering (T) — any device, no trace     │
│ 2. Full PHI disclosure (I) — 30 seconds via DevTools       │
│ 3. Admin PIN brute-force (S) — 10,000 attempts, no lock    │
│ 4. Default PIN exposure (I) — readable in public source    │
│ 5. Mass patient deletion (D) — single API call             │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Attack Tree Analysis

### 2.1 Goal: Access Any Patient Ward Without Authorization

```
[ROOT] Access patient ward without valid PIN
├── [A] Read PINs from Firebase (probability: HIGH)
│   ├── [A1] Open app in browser                    → automatic anonymous auth
│   ├── [A2] Open DevTools console
│   └── [A3] firebase.database().ref('pins').once('value')
│           → returns all 11 PINs instantly
│
├── [B] Read default PINs from source code (probability: CERTAIN)
│   ├── [B1] View page source                       → find PINS constant line 326
│   └── [B2] Use "1111" for A_M, "0000" for ADMIN   → immediate access
│
├── [C] Brute-force PIN (probability: HIGH if above fail)
│   ├── [C1] Write script to call checkPin() 10,000 times
│   ├── [C2] No rate limit, no lockout
│   └── [C3] 4-digit space exhausted in < 1 second programmatically
│
└── [D] Social engineering (probability: MEDIUM)
    ├── [D1] Observe nurse entering PIN (shoulder surfing)
    └── [D2] Call support pretending to be admin
```

### 2.2 Goal: Corrupt Patient Data During MCI

```
[ROOT] Corrupt triage data during mass casualty incident
├── [A] Direct Firebase manipulation
│   ├── [A1] Authenticate anonymously (automatic)
│   ├── [A2] Iterate all units, set all codes to 1 (Green)
│   │       → All critical patients appear stable
│   │       → Staff stop prioritizing emergencies
│   └── [A3] No alert triggered; takes minutes to notice
│
├── [B] OCR import poisoning
│   ├── [B1] Gain physical access to admin device
│   ├── [B2] Prepare image with deliberately wrong triage codes
│   ├── [B3] Use OCR import to batch-import fake patients
│   └── [B4] Real patients displaced/confused in system
│
└── [C] Offline cache poisoning
    ├── [C1] Access unlocked device running MedEvac
    ├── [C2] Open DevTools, modify localStorage directly
    ├── [C3] Corrupt `mak_patients_*` values
    └── [C4] Device shows corrupted data until online sync
```

### 2.3 Goal: Achieve Persistent Access

```
[ROOT] Maintain persistent unauthorized access
├── [A] PIN never expires → access retained indefinitely
├── [B] No session binding to device → any device with PIN works
└── [C] No concurrent session detection → invisible parallel access
```

---

## 3. Clinical Safety — Failure Mode & Effects Analysis (FMEA)

FMEA rates each failure by **Severity (S)**, **Occurrence (O)**, and **Detection (D)** on a 1–10 scale. Risk Priority Number (RPN) = S × O × D.

### 3.1 FMEA Table

| # | Failure Mode | Effect | S | O | D | RPN | Current Control |
|---|-------------|--------|---|---|---|-----|-----------------|
| F-01 | OCR misreads triage code | Critical patient classified as Stable | 10 | 6 | 8 | **480** | Manual confirmation step |
| F-02 | Triage code tampered externally | Wrong resource allocation | 10 | 5 | 9 | **450** | None |
| F-03 | Patient added to wrong unit/gender | Patient untraceable | 8 | 5 | 7 | **280** | Unit shown in header |
| F-04 | Duplicate Civil ID accepted | Two records for same patient | 7 | 6 | 8 | **336** | No duplicate check |
| F-05 | Offline edit conflicts with online edit | Newer data silently overwritten | 8 | 4 | 9 | **288** | None (last-write-wins) |
| F-06 | Session timeout mid-edit | Patient edit lost without save | 6 | 5 | 5 | **150** | Timeout warning modal |
| F-07 | Backup PNG downloaded with unmasked civil IDs | PHI stored on personal device | 7 | 7 | 7 | **343** | PNG contains full IDs |
| F-08 | OCR default triage code 2 applied | Under-triaged patients | 9 | 5 | 6 | **270** | No visual warning |
| F-09 | Ward field free-text allows ambiguous location | Staff cannot locate patient | 6 | 6 | 6 | **216** | No ward format validation |
| F-10 | App crash during active emergency | Loss of patient visibility | 9 | 2 | 5 | **90** | Offline cache fallback |
| F-11 | firebase `onValue` fires stale data on reconnect | Staff see outdated critical status | 7 | 4 | 7 | **196** | Real-time sync overrides |
| F-12 | Patient deleted by wrong user | Patient data permanently lost | 9 | 3 | 4 | **108** | Confirmation dialog |
| F-13 | Codes 3 and 4 same red color | Red vs Critical indistinguishable | 7 | 7 | 4 | **196** | Numeric code label shown |
| F-14 | Search returns patient from wrong filter | Clinician misses critical patient | 8 | 3 | 5 | **120** | Filter + search combined |
| F-15 | App shows offline but queue not syncing | Edits appear saved, actually lost | 8 | 3 | 8 | **192** | None |

### 3.2 Top RPN Findings

```
RPN > 300 — Requires immediate action:
  F-01 (480): OCR triage misread            → Add OCR confidence warning
  F-02 (450): External triage tampering     → Require named auth for writes
  F-04 (336): Duplicate patients            → Civil ID uniqueness check
  F-07 (343): PHI in PNG backup             → Mask civil IDs in export
  F-03 (280): Wrong unit entry              → Confirmation step on patient add
```

### 3.3 Critical Clinical Safety Deficiencies

#### 3.3.1 No Triage Timestamp — F-16 (NEW)

**Location:** Patient record schema

Every patient record has a `ts` field for creation/modification time. However, **there is no separate timestamp for triage code changes**. In a fast-moving emergency:

- A patient triaged as Yellow (2) at 14:00 then upgraded to Critical (4) at 14:45 has the same `ts` updated
- No history of triage escalations is preserved
- Clinical staff cannot review triage progression
- Medico-legal review cannot reconstruct the timeline

**RPN:** 8 × 4 × 9 = **288**
**Recommendation:** Add `code_ts` and `code_history[]` to patient record schema.

#### 3.3.2 OCR Default Code 2 Is Clinically Dangerous — F-08

**Location:** `index.html:518`

```javascript
code: +p.code || 2
```

When the AI cannot determine a triage code from an image, it defaults to **2 (Yellow/Moderate)**. This is the wrong safe default. In triage, the safe direction is **to over-triage** (assume worse) rather than under-triage. A patient who is actually Critical (4) but comes in as Code 2 via OCR could be missed during a busy incident.

**Recommendation:** Default to `4` (Critical) if OCR cannot determine code, force manual confirmation for any patient with a defaulted code, and flag them visually.

#### 3.3.3 No Allergy / Contraindication Field — F-17 (NEW)

The patient schema contains no field for known allergies, medications, or contraindications. In an emergency department context, this is a critical clinical gap. Staff using this system as the sole reference for a patient would have no visibility into drug contraindications.

**Clarification needed:** Is MedEvac intended as a triage tracker only (not a full clinical record)? If so, this must be clearly documented so staff understand what it is and is not.

---

## 4. Usability Heuristic Evaluation

Evaluated against Nielsen's 10 Usability Heuristics.

### 4.1 Heuristic Scores

| # | Heuristic | Score (1–5) | Finding |
|---|-----------|-------------|---------|
| H-01 | Visibility of system status | 3/5 | Online/offline indicator present; no sync progress visible |
| H-02 | Match between system and real world | 4/5 | Arabic labels, triage color codes match clinical convention |
| H-03 | User control and freedom | 2/5 | **No undo for delete**; no draft saving; session timeout loses in-progress forms |
| H-04 | Consistency and standards | 3/5 | "Back" button behavior differs: sometimes goes home, sometimes goes to ward |
| H-05 | Error prevention | 2/5 | **No Civil ID format validation**; OCR imports with wrong codes silently |
| H-06 | Recognition over recall | 4/5 | Patient list clear; triage codes visible; good visual hierarchy |
| H-07 | Flexibility and efficiency | 3/5 | No keyboard shortcuts; no quick-edit from list view |
| H-08 | Aesthetic and minimalist design | 5/5 | Clean, uncluttered; excellent visual design |
| H-09 | Help users recognize/diagnose/recover from errors | 2/5 | **Toast messages disappear in 2.5s**; no error detail; no retry mechanism |
| H-10 | Help and documentation | 2/5 | FAQ page is inaccurate; no contextual help in-app |

### 4.2 Critical Usability Findings

#### H-03: No Undo — Clinical Safety Risk

When a patient is deleted, the confirmation dialog says "Delete?" with a trash icon. After confirming, the record is **permanently and immediately removed** from Firebase with no undo. During a chaotic emergency scenario:

- A nurse intending to delete one patient could mis-tap and delete another
- The confirmation only shows the patient name, which may be hard to read quickly
- No grace period (e.g., "Deleting in 5 seconds... Undo") is offered

**Recommendation:** Implement 5-second undo with offline-queue cancellation support.

#### H-09: Toast Disappears Too Fast

```javascript
// index.html:414
window._tt = setTimeout(() => e.classList.remove("show"), 2500);
```

Error toasts vanish in 2.5 seconds. In an emergency environment:
- Staff are often looking at a patient, not a screen
- A failed-save error could be completely missed
- The user believes data is saved when it is not

**Recommendation:** Error toasts should persist until dismissed. Success toasts can auto-dismiss.

#### H-04: Inconsistent Back Button Behavior

The back button (`bb`) has different behavior depending on context:
- From `ward` → goes to `home`
- From `detail` → goes to `ward`
- From `add` → goes to `ward`
- From `pin` → goes to `home`
- From `admin` → goes to `home`

There is no breadcrumb or title that tells users where "back" will take them. This is a workflow hazard in an emergency.

### 4.3 Emergency Environment Specific Concerns

| Concern | Impact |
|---------|--------|
| No glove-mode / large-touch mode | Clinical staff wearing PPE gloves cannot tap 36px buttons reliably |
| No voice input | Cannot add patients hands-free |
| Bright screen on dark ward | No dark/night mode adaptation |
| No barcode/QR scan for patient wristband | Manual civil ID entry error-prone |
| Single-column layout wastes tablet screen | Tablet users see same narrow 430px view |
| No "handoff" or shift-change feature | Outgoing nurse cannot flag items for incoming shift |

---

## 5. Logic & Race Condition Audit

### 5.1 Race Condition: Auth Not Ready When Firebase Accessed

**Location:** `index.html:269-273`

```javascript
let _authReady = false, _authUid = null;
onAuthStateChanged(auth, u => { _authUid = u?.uid; _authReady = true; });
signInAnonymously(auth).catch(e => console.warn("Auth failed", e));

// Immediately after:
get(ref(db, "config/geminiKey")).then(s => { ... });
```

The `get(ref(db, "config/geminiKey"))` call fires **before** `onAuthStateChanged` has confirmed authentication. If the Firebase Security Rules require `auth != null` for `config`, this read may fail silently because authentication hasn't completed yet.

**Impact:** Gemini API key may not load on slow devices, causing OCR to fail with no useful error message.

**Fix:** Wrap Gemini key fetch inside the `onAuthStateChanged` callback:
```javascript
onAuthStateChanged(auth, u => {
  _authUid = u?.uid;
  _authReady = true;
  if (u) get(ref(db, "config/geminiKey")).then(s => { if(s.exists()) GK = s.val(); });
});
```

### 5.2 Race Condition: `_bp` Flag and Backup PNG

**Location:** `index.html:393-398`

```javascript
function listenUnit(uid) {
  ...
  S._bp = true;   // flag set
  onValue(ref(db, "patients/" + uid), snap => {
    ...
    if (S._bp && S.patients.length > 0) {
      S._bp = false;
      setTimeout(() => { backupPNG(); }, 500);  // auto-download
    }
  });
}
```

Every time a user logs into a unit, `S._bp = true`, which causes **an automatic PNG download** to trigger after the patient list loads. This means:

1. Every login silently downloads a PNG containing all patient civil IDs
2. Staff may not notice this download happening
3. On shared/hospital devices, these files accumulate in the Downloads folder with no cleanup
4. If the device is used by multiple people, PHI accumulates for all of them

**This is a significant, undisclosed PHI leakage mechanism.**

**Severity:** HIGH (Clinical Safety + Privacy)
**Fix:** Remove automatic backup on login. Backup should be explicitly user-initiated only.

### 5.3 Race Condition: Simultaneous `render()` Calls

When a Firebase `onValue` listener fires at the same time as a user interaction:
```
User taps patient → render() called → S.screen = "detail"
Firebase fires    → render() called → if(S.screen==="ward") render()
```

If the Firebase update fires during the transition (e.g., user just tapped a patient card), both `render()` calls may execute near-simultaneously, with the second one potentially overwriting the first. Since `render()` does `app.innerHTML = h` and `bindAll()`, this can:
- Reset the screen to `ward` while the user is on `detail`
- Cause double-binding of event listeners in edge cases

**Severity:** LOW (intermittent UX glitch, not clinical safety issue)

### 5.4 Logic Flaw: Filter "Red" Includes Code 3 and Code 4

**Location:** `index.html:416`

```javascript
function filtered() {
  ...
  if (S.filter === "r") l = l.filter(p => p.code >= 3);
  ...
}
```

The filter tab is labeled "Red" but captures codes 3 AND 4. The tab counter also shows the combined red+critical count. However, the stats row labels it "Red" — a clinician filtering for "urgent" patients may not realize they're also seeing "Critical" patients and vice versa. Given that Codes 3 and 4 use the same color, this conflation is compounded.

**Clinical Risk:** A nurse filtering for "Red" might see 5 patients, not realizing 3 are Critical (code 4) requiring immediate attention.

**Recommendation:** Separate filter tabs for Red (3) and Critical (4) with distinct colors.

### 5.5 Logic Flaw: Patient Sort Is Unstable During Edits

**Location:** `index.html:416`

```javascript
return l.sort((a, b) => b.code - a.code);
```

Patients are sorted by triage code descending (Critical first). When a nurse opens a patient for editing, the `S.editP` reference is set to `S.patients.find(x => x._k === key)`. If another user simultaneously changes that patient's triage code, the patient moves position in the sorted list. When the editor saves and returns to the ward view, the patient they just edited may appear in a different position than expected, causing brief disorientation.

**Severity:** LOW

### 5.6 Logic Flaw: Admin `listenAll` Never Cleaned Up

**Location:** `index.html:399-407`

```javascript
let _listenAllDone = false;
function listenAll() {
  if (_listenAllDone) return;
  _listenAllDone = true;
  onValue(ref(db, "patients"), ...);
  onValue(ref(db, "pins"), ...);
}
```

Once `listenAll()` runs, `_listenAllDone` is permanently `true`. If the admin logs out and back in, `listenAll()` is a no-op. But the listeners from the first session are still firing. The listener closures capture `S` (the global state object), so they will continue updating `S.allData` even if the user has navigated to a ward screen, potentially causing unexpected re-renders.

**Severity:** LOW

### 5.7 Logic Flaw: `beforeunload` Wipes State But Not DOM

**Location:** `index.html:428`

```javascript
window.addEventListener("beforeunload", () => {
  S.patients = [];
  S.allData = {};
  S.editP = null;
});
```

This clears in-memory data on page unload. However, the DOM (`app.innerHTML`) still holds the rendered patient HTML at the moment of unload. On some browsers (particularly with "back/forward cache" / bfcache), the page can be restored from cache with the DOM intact. If bfcache restores the page, PHI is visible in the DOM even though `S.patients` is empty.

**Fix:** Add a visibility-change listener to clear the DOM, or use `sessionStorage` for screen state and re-render on restore.

---

## 6. PWA Manifest & Install Audit

### 6.1 Manifest Analysis

**File:** `manifest.json`

```json
{
  "name": "MedEvac",
  "short_name": "MedEvac",
  "start_url": "/",
  "display": "standalone",
  "orientation": "portrait",
  "background_color": "#f8f9fc",
  "theme_color": "#0a0a0f",
  "lang": "ar",
  "dir": "rtl",
  "categories": ["medical"],
  "icons": [
    { "src": "icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable" },
    { "src": "icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable" }
  ]
}
```

### 6.2 Manifest Issues

| Issue | Severity | Detail |
|-------|----------|--------|
| `purpose: "any maskable"` on both icons | MEDIUM | `any` and `maskable` should be separate icon entries. Combining them means browsers may crop the icon incorrectly as a maskable icon. |
| `theme_color` mismatch | LOW | Manifest has `#0a0a0f`; `index.html` meta tag has `#0f172a`; `ViewController.swift` uses `(0.059, 0.09, 0.165)`. Three different values for the same conceptual color. |
| `background_color` mismatch | LOW | Manifest `#f8f9fc`; actual app background CSS variable `--bg: #f1f5f9`. Users see a flash of `#f8f9fc` during PWA launch. |
| No `scope` defined | LOW | Defaults to `/`; intentional but worth documenting. |
| No `screenshots` defined | LOW | Reduces discoverability in app store-like PWA installers. |
| No `description` localization | LOW | Single English description despite app being Arabic-first. |
| `orientation: "portrait"` | LOW | iPad supports landscape in Info.plist; this conflicts. |

### 6.3 iOS App Icon Coverage Gap

**File:** `Assets.xcassets/AppIcon.appiconset/Contents.json`

The icon set only contains:
- `icon-1024.png` (App Store)
- `icon-76.png` (iPad 1x)
- `icon-152.png` (iPad 2x)
- `icon-167.png` (iPad Pro)

**Missing required iPhone icons:**
- `icon-60@2x.png` (120×120) — iPhone home screen
- `icon-60@3x.png` (180×180) — iPhone home screen @3x
- `icon-40@2x.png` (80×80) — Spotlight
- `icon-40@3x.png` (120×120) — Spotlight @3x
- `icon-20@2x.png` (40×40) — Notification
- `icon-20@3x.png` (60×60) — Notification @3x

**Impact:** The app may display a generic placeholder icon on iPhone home screens, appearing unprofessional and reducing staff confidence. Xcode 15+ may reject the build or show warnings.

**Note:** The Codemagic pipeline generates these at build time via `sips`, so they exist in the built IPA. But the repository state is incomplete.

---

## 7. Database Rules — Edge Case Analysis

### 7.1 Rule Gaps Not Covered in Volume II

#### 7.1.1 Patient Record Can Be Created With Empty Name Via Whitespace

**Rule:** `name.length > 0`

A name containing only spaces (e.g., `"   "`) would pass the validation since `"   ".length > 0`. However, the UI would display a blank patient name, which is clinically dangerous.

**Fix:** Add `.trim()` validation or a non-whitespace regex in Firebase rules:
```json
"name": { ".validate": "newData.isString() && newData.val().trim().length > 0 && newData.val().length <= 200" }
```

#### 7.1.2 Civil ID Has No Format Validation

**Rule:** `civil.length <= 20` (only a length check)

Kuwait Civil ID numbers follow the format: 12 digits, first digit encodes birth century. Any string up to 20 characters passes, including letters, symbols, or all zeros (`"000000000000"`).

**Fix:** Add regex validation:
```json
"civil": { ".validate": "newData.isString() && newData.val().length <= 20 && newData.val().matches(/^[0-9]{10,12}$/)" }
```

#### 7.1.3 Timestamp Not Validated as Reasonable Value

**Rule:** `ts.isNumber()`

The `ts` field can be any number — including 0, negative numbers, or far-future dates like `9999999999999`. An attacker could set all patient timestamps to 0, breaking sort order or date displays.

**Fix:**
```json
"ts": { ".validate": "newData.isNumber() && newData.val() > 1000000000000 && newData.val() < now + 60000" }
```
(Must be after 2001 and no more than 60 seconds in the future)

#### 7.1.4 PIN Validation Allows 4–6 Digit Plaintext or 64-Char Hash — Ambiguous

**Rule:**
```json
"$pin": {
  ".validate": "... (newData.val().length == 64 || (newData.val().length >= 4 && newData.val().length <= 6))"
}
```

The rule explicitly allows both hashed (64-char) and plaintext (4–6 char) PINs. This means the system permanently supports insecure plaintext PINs at the database layer, even after a migration to hashed PINs.

**Fix:** Once migration is complete, restrict to 64-char hashes only:
```json
"$pin": { ".validate": "newData.val().length == 64 && newData.val().matches(/^[a-f0-9]{64}$/)" }
```

#### 7.1.5 Audit Log Entry Has No User-Agent Validation Length

**Rule:** The audit entry allows any string/number for `$field`. The client sends `ua: navigator.userAgent.slice(0,80)`, but the rule doesn't enforce a maximum length. A malicious write could send a 500KB string as the `detail` field.

**Fix:** Add length constraints to audit fields:
```json
"detail": { ".validate": "newData.isString() && newData.val().length <= 500" }
```

---

## 8. iOS Icon & App Store Compliance

### 8.1 Medical App Category

**Location:** `Info.plist:118`

```xml
<key>LSApplicationCategoryType</key>
<string>public.app-category.medical</string>
```

Apps in the **Medical** category on the App Store are subject to Apple's enhanced review process and require:

1. **Privacy manifest** (`PrivacyInfo.xcprivacy`) — Not present in the repository
2. **Purpose strings for any camera/microphone access** — The OCR feature uses camera; no `NSCameraUsageDescription` key is in `Info.plist`
3. **Disclaimer** that the app is not a replacement for professional medical advice

**Impact:**
- App will be **rejected** by App Store Review without `NSCameraUsageDescription`
- App may be rejected without a privacy manifest
- Medical category requires regulatory compliance evidence

**Fix:** Add to `project.yml` info properties:
```yaml
NSCameraUsageDescription: "MedEvac uses the camera to scan patient registration documents for OCR import."
NSPhotoLibraryUsageDescription: "MedEvac can import patient documents from your photo library."
```

### 8.2 `ITSAppUsesNonExemptEncryption: false` — Inaccurate Declaration

**Location:** `Info.plist:115-116` and `project.yml:35`

```xml
<key>ITSAppUsesNonExemptEncryption</key>
<false/>
```

This declaration states the app does **not** use non-exempt encryption. However:
- The app uses HTTPS (TLS) for all communications
- The app uses `crypto.subtle.digest` (SHA-256) for PIN hashing
- Firebase SDK itself uses encryption internally

HTTPS is exempt encryption under US EAR regulations, so this may technically be correct. However, SHA-256 usage in the app code should be reviewed by legal counsel familiar with US export regulations before App Store submission.

### 8.3 `armv7` Architecture Requirement Is Outdated

**Location:** `Info.plist:32-34`

```xml
<key>UIRequiredDeviceCapabilities</key>
<array>
    <string>armv7</string>
</array>
```

`armv7` refers to 32-bit devices (iPhone 5s era). Apple dropped 32-bit app support in iOS 11 (2017) and all modern iPhones are arm64. This requirement:
- Has no practical effect (all supported devices have armv7+ capability)
- Should be updated to `arm64` to accurately reflect requirements
- May trigger App Store review questions

---

## 9. Triage Protocol Alignment

### 9.1 Comparison with START Triage

The START (Simple Triage And Rapid Treatment) protocol uses 4 categories:

| START Category | Color | MedEvac Code | Alignment |
|---------------|-------|-------------|-----------|
| Immediate | Red | 3 (Red) | PARTIAL — START Red = life-threatening; MedEvac has a separate Critical (4) |
| Delayed | Yellow | 2 (Yellow) | PASS |
| Minor | Green | 1 (Green) | PASS |
| Expectant/Deceased | Black | **Not present** | **FAIL** |

**Critical Gap: No Code 0 / Black Tag (Expectant)**

MedEvac has no mechanism for marking a patient as "Expectant" (survival unlikely, resources better used elsewhere) or "Deceased." In a mass casualty incident, this is a fundamental triage category.

**Current Workaround:** Staff would have to delete the patient record or use notes. Both are clinically unacceptable — deletion destroys the record, and notes-based status is not machine-readable.

**Recommendation:** Add Code 0 (Black/Expectant) and Code 5 (Deceased/White) to the triage system.

### 9.2 Comparison with Kuwait MOH Emergency Protocol

Kuwait's Ministry of Health emergency triage uses a 5-level Emergency Severity Index (ESI):

| ESI Level | Description | MedEvac Equivalent |
|-----------|-------------|-------------------|
| 1 | Immediate (life-saving) | Code 4 (Critical) |
| 2 | Emergent | Code 3 (Red) — **no direct equivalent** |
| 3 | Urgent | Code 2 (Yellow) — **no direct equivalent** |
| 4 | Less Urgent | Code 1 (Green) |
| 5 | Non-Urgent | **Not present** |

**The 4-code system does not map cleanly to Kuwait's 5-level ESI.** Staff trained on ESI would need to mentally re-map categories, introducing cognitive load and potential error in high-stress situations.

**Recommendation:** Align triage codes with Kuwait MOH ESI or provide a clear mapping document.

---

## 10. Backup PNG — Data Leakage Analysis

### 10.1 Automatic Download Behavior

**Location:** `index.html:393-398` (the `_bp` flag) and `index.html:430-443` (`backupPNG()`)

As identified in Section 5.2, a PNG is **automatically downloaded every time a user logs into a unit**. This PNG contains:

```
Column layout in backup PNG:
#  |  Name  |  Civil ID  |  Nationality  |  Ward  |  Code  |  Notes
```

**Civil IDs are NOT masked in the backup PNG.** While the ward view shows masked civil IDs (`264•••••097`), the `backupPNG()` function uses:
```javascript
const cols = ["#","Name","Civil ID","Nat","Ward","Code","Notes"];
const rows = pts.map((p,i) => ["" + (i+1), p.name || "", p.civil || "", ...]);
```

The raw, unmasked civil ID is written to canvas and exported.

### 10.2 PNG Accumulation Risk

| Scenario | Risk |
|----------|------|
| Nurse logs into Ward A_M — PNG auto-downloaded | PHI on device |
| Same nurse logs into A_F — second PNG | PHI on device |
| Nurse's personal phone used | PHI on personal device, not hospital-managed |
| Android auto-backup enabled | PHI backed up to Google Drive |
| Screenshot taken of PNG | PHI in camera roll |
| PNG shared via WhatsApp to colleague | PHI transmitted via non-secure channel |
| Device lost | PHI accessible to finder |

### 10.3 Recommendation

1. Remove automatic backup — make it strictly manual
2. Mask civil IDs in PNG output (show only last 4 digits)
3. Add a watermark with timestamp and accessing UID
4. Log PNG generation to the audit trail
5. Add a PIN confirmation before PNG generation
6. Store in a secure, managed location rather than device Downloads folder

---

## 11. Session & Timeout Behavior Analysis

### 11.1 Timeout Implementation

**Location:** `index.html:419-421`

```javascript
const TO = 5 * 60 * 1000;  // 5 minutes
let _tmr;

function resetT() {
  clearTimeout(_tmr);
  if (S.screen !== "home" && S.screen !== "pin")
    _tmr = setTimeout(() => {
      $("tr").innerHTML = '... Session Expired ...';
    }, TO);
}

["click","touchstart","keydown","scroll"].forEach(e =>
  document.addEventListener(e, resetT, {passive: true}));
```

### 11.2 Timeout Gap: Active Firebase Listener Is Not Inactivity

The timeout resets on user interaction (click, touch, keydown, scroll). But `onValue` Firebase listeners fire automatically without user interaction. If Firebase sends updates (another device edited a patient), this does NOT reset the inactivity timer. The timer measures true inactivity. **This is correct behavior** — PASS.

### 11.3 Timeout Gap: 5 Minutes Too Long for Shared Devices

In an emergency department where multiple staff share devices, 5 minutes is a long time to leave PHI on-screen. HIPAA guidance recommends automatic logoff after a period of inactivity, but does not specify a duration. Clinical context suggests 2 minutes would be more appropriate for a busy shared-device environment.

### 11.4 Timeout Gap: Timer Starts from Page Load, Not Login

**Location:** `index.html:449`

```javascript
function render() {
  ...
  app.innerHTML = h;
  bindAll();
  resetT();  // timer resets on every render
}
```

`resetT()` is called by `render()`, which is called by `boot()` at startup. So the timer starts running from initial page load, even on the home screen where no PHI is visible. The condition `if (S.screen !== "home")` correctly handles this — on the home screen, `_tmr` is cleared, not set. **PASS.**

### 11.5 Timeout Gap: PIN Screen Not Protected by Timer

```javascript
if (S.screen !== "home" && S.screen !== "pin")
  _tmr = setTimeout(...)
```

The PIN entry screen is excluded from the timeout. This means a device left on the PIN entry screen is not auto-locked. However, the PIN screen shows no PHI, so this is acceptable behavior. **PASS.**

### 11.6 Timeout Modal Can Be Dismissed Without Re-Auth

**Location:** `index.html:420-421`

```javascript
_tmr = setTimeout(() => {
  $("tr").innerHTML = '...<button class="btn" onclick="window._ul()">Return Home</button>...';
}, TO);

window._ul = () => { $("tr").innerHTML = ""; S.screen = "home"; ... render(); };
```

The timeout modal sends the user back to **Home**, which is correct. It does not allow them to resume the session. **PASS.**

---

## 12. Offline Queue — Integrity & Ordering Guarantees

### 12.1 Queue Structure

```javascript
// Each queue item:
{ type: "set" | "remove" | "push", path: string, data: object }
```

### 12.2 Queue Ordering Issues

**Location:** `index.html:297-309`

The sync queue processes operations in FIFO order. This is correct for most cases, but consider this scenario:

```
Offline sequence:
  1. Nurse adds patient P1              → push /patients/A_M
  2. Nurse edits patient P1 (triage 1→3) → BUT P1's key is "off_1234" (offline key)
     → set /patients/A_M/off_1234        → uses offline-generated key
  3. Sync runs → push creates P1 with Firebase key "-NXabc"
  4. set /patients/A_M/off_1234 runs → creates ORPHAN record (wrong key)
```

**Impact:** When a patient is added offline and then edited offline before sync, the edit targets the offline key (`off_timestamp`). When synced, the push creates the patient with a real Firebase key, and the edit creates a second orphan record at the offline key path.

**Severity:** HIGH (data duplication, patient appearing twice)
**Fix:** After a successful offline `push`, update the queue to replace the offline key in any subsequent operations.

### 12.3 Queue Survives Session Timeout

```javascript
// Sync queue stored in localStorage, persists across sessions
LS.queueOp(op);
```

If a nurse's session times out while offline operations are queued, those operations will sync when any user next opens the app and goes online — regardless of who that user is. A different nurse could inadvertently trigger the previous nurse's pending operations.

**Severity:** MEDIUM
**Fix:** Tag queued operations with the session UID and only sync operations matching the current session.

### 12.4 No Queue Size Limit

```javascript
function queueOp(op) {
  const q = LS.load("queue") || [];
  q.push(op);
  LS.save("queue", q);
}
```

There is no maximum queue size. During a prolonged outage, hundreds of operations could accumulate. `LS.save()` silently fails if localStorage is full — the queue would be truncated without warning, causing data loss.

**Severity:** MEDIUM

---

## 13. Social Engineering & Physical Security

### 13.1 Physical Security Vectors

| Vector | Risk | Mitigation |
|--------|------|------------|
| Shoulder surfing PIN entry | HIGH | 5-minute timeout; PIN dots obscure entry |
| Shared device left unlocked | HIGH | 5-min timeout, but 5 min is long |
| Staff sharing PINs verbally | HIGH | None — PIN is a shared secret per unit |
| Screenshot of patient list | HIGH | No screenshot prevention |
| Screen recording during app use | HIGH | No prevention |
| Visitor using unattended device | MEDIUM | Timeout; home screen shows no PHI |
| Photo of screen with external camera | HIGH | No prevention possible |

### 13.2 Social Engineering Vulnerabilities

The support page explicitly describes:

```
"Forgot your PIN? Contact the system administrator to reset via admin panel."
```

An attacker could:
1. Call the hospital IT desk claiming to be a nurse who forgot their PIN
2. Request an admin to reveal or reset a unit PIN
3. Use the new PIN to access patient data

**There is no identity verification process described for PIN resets.** The admin panel shows all PINs in plaintext password input fields (which can be revealed with the browser's "show password" button).

### 13.3 PIN Displayed in Admin Panel Input Fields

**Location:** `index.html:481`

```javascript
'<input class="fi" id="p-' + uid + '" value="' + (S.pins[uid] || "") + '" ' +
'maxlength="6" type="password" style="..." autocomplete="off">'
```

The PIN is set as the `value` attribute of a `type="password"` input. On most browsers:
- The "Show Password" eye button reveals the PIN in one click
- Browser autofill may log the PIN as a credential
- The PIN value is in the DOM and readable via `document.getElementById('p-ADMIN').value`

**Severity:** HIGH — any user who gains admin access can reveal all PINs via browser DevTools in one line: `document.querySelectorAll('input[type=password]').forEach(i => console.log(i.id, i.value))`

---

## 14. Findings Volume III

| ID | Finding | Severity | Category |
|----|---------|----------|----------|
| **W-01** | STRIDE: Triage tampering (set code 1 for all patients) | CRITICAL | Threat Model |
| **W-02** | Auto-download PNG on every login leaks unmasked civil IDs | HIGH | Privacy |
| **W-03** | Civil IDs not masked in backup PNG export | HIGH | Privacy |
| **W-04** | Offline queue creates duplicate patient on add→edit→sync | HIGH | Data Integrity |
| **W-05** | OCR default triage code 2 is clinically unsafe | HIGH | Clinical Safety |
| **W-06** | No Expectant/Deceased triage category (Code 0/5) | HIGH | Clinical Safety |
| **W-07** | All PINs visible in admin panel via "show password" button | HIGH | Security |
| **W-08** | iOS app missing NSCameraUsageDescription — App Store rejection | HIGH | Compliance |
| **W-09** | Race condition: Firebase auth not ready when Gemini key fetched | MEDIUM | Reliability |
| **W-10** | Triage codes don't align with Kuwait ESI 5-level protocol | MEDIUM | Clinical Safety |
| **W-11** | No triage change timestamp — no escalation audit trail | MEDIUM | Clinical Safety |
| **W-12** | Error toasts vanish in 2.5s — failed saves missed by staff | MEDIUM | Usability |
| **W-13** | Session queue syncs on next user's session — cross-session pollution | MEDIUM | Data Integrity |
| **W-14** | No undo for patient deletion | MEDIUM | Usability / Safety |
| **W-15** | Manifest `purpose: "any maskable"` on same icon entry | MEDIUM | PWA |
| **W-16** | PWA background/theme color mismatch causes launch flicker | LOW | UX |
| **W-17** | Firebase rules allow whitespace-only patient names | LOW | Data Integrity |
| **W-18** | Firebase rules allow any timestamp value (including 0) | LOW | Data Integrity |
| **W-19** | Firebase rules permanently allow plaintext PINs | LOW | Security |
| **W-20** | bfcache may restore PHI-containing DOM after session end | LOW | Privacy |
| **W-21** | `armv7` device capability declaration is outdated | LOW | iOS |
| **W-22** | No glove-mode / enlarged touch targets for PPE use | LOW | Usability |
| **W-23** | Filter "Red" conflates Code 3 and Code 4 patients | LOW | Clinical Safety |

---

## 15. Master Findings Table — All Three Volumes

| ID | Finding | Severity | Volume |
|----|---------|----------|--------|
| C-1 | Hardcoded default PINs in client JavaScript | CRITICAL | I |
| C-2 | XOR offline encryption is not cryptographic | CRITICAL | I |
| C-3 | No per-user authentication / RBAC | CRITICAL | I |
| V-01 | XSS via error handler innerHTML injection | CRITICAL | II |
| V-03 | PIN plaintext fallback enables offline bypass | CRITICAL | II |
| V-08 | Hardcoded fallback keystore password `medevac123` | CRITICAL | II |
| W-01 | Triage tampering: any device can set all patients to Green | CRITICAL | III |
| C-4 | No PIN brute-force rate limiting | HIGH | I |
| C-5 | Firebase anonymous auth, no user identity | HIGH | I |
| C-6 | Hardcoded salt for PIN hashing | HIGH | I |
| C-7 | No automated test suite | HIGH | I |
| C-8 | No HIPAA/Kuwait compliance framework | HIGH | I |
| V-06 | Seed data with real-looking patient PHI in source | HIGH | II |
| V-09 | New Android keystore generated per build | HIGH | II |
| W-02 | Auto-download PNG on every login — unmasked civil IDs | HIGH | III |
| W-03 | Civil IDs not masked in backup PNG | HIGH | III |
| W-04 | Offline queue: add→edit→sync creates duplicate patients | HIGH | III |
| W-05 | OCR default triage code 2 is clinically under-safe | HIGH | III |
| W-06 | No Expectant/Deceased triage category | HIGH | III |
| W-07 | All PINs visible via admin panel show-password button | HIGH | III |
| W-08 | Missing NSCameraUsageDescription — App Store rejection | HIGH | III |
| C-9 | `unsafe-inline` in CSP | MEDIUM | I |
| C-10 | No data retention / purge policy | MEDIUM | I |
| V-02 | DOM XSS possible in confirm dialog | MEDIUM | II |
| V-04 | Gemini API key readable by any client | MEDIUM | II |
| V-05 | Cross-domain localStorage key mismatch | MEDIUM | II |
| V-07 | No client-side input validation | MEDIUM | II |
| V-10 | iOS ATS config conflict (project.yml vs Info.plist) | MEDIUM | II |
| V-11 | Firebase Auth SDK not precached in Service Worker | MEDIUM | II |
| V-12 | Support page contradicts offline capability | MEDIUM | II |
| V-13 | No staging environment; pushes go directly to production | MEDIUM | II |
| V-14 | Android allowBackup=true exposes data via ADB | MEDIUM | II |
| V-15 | Silent auth failure with no user notification | MEDIUM | II |
| W-09 | Race: auth not ready when Gemini key is fetched | MEDIUM | III |
| W-10 | Triage codes don't align with Kuwait ESI protocol | MEDIUM | III |
| W-11 | No triage escalation timestamp / history | MEDIUM | III |
| W-12 | Error toasts vanish too fast — saves may be missed | MEDIUM | III |
| W-13 | Queue syncs on next user's session (cross-session pollution) | MEDIUM | III |
| W-14 | No undo for patient deletion | MEDIUM | III |
| W-15 | Manifest icon `purpose: "any maskable"` incorrect | MEDIUM | III |
| V-other | 4 low-severity findings from Volume II | LOW | II |
| W-16–23 | 8 low-severity findings from Volume III | LOW | III |

### Summary Totals

| Severity | Vol. I | Vol. II | Vol. III | **Total** |
|----------|--------|---------|----------|-----------|
| CRITICAL | 3 | 3 | 1 | **7** |
| HIGH | 5 | 2 | 7 | **14** |
| MEDIUM | 2 | 9 | 7 | **18** |
| LOW | 0 | 4 | 8 | **12** |
| **Total** | **10** | **18** | **23** | **51** |

---

## 16. Executive Remediation Priority Matrix

The following groups findings into deployment gates. The system **must not go live** until Gate 1 is cleared.

### Gate 1 — Block Deployment (Do Before Any Hospital Use)

| Finding | Action | Owner | Estimate |
|---------|--------|-------|----------|
| C-1: Hardcoded PINs | Remove from source; force reset on first login | Backend | 1 day |
| C-2: XOR encryption | Replace with AES-GCM (Web Crypto API) | Frontend | 2 days |
| V-01: XSS in errors | Replace `innerHTML` with `textContent` in `showFatal()` | Frontend | 2 hours |
| V-03: PIN fallback bypass | Remove `\|\| PINS[target]` fallback | Frontend | 1 hour |
| V-08: Keystore password | Remove `:-medevac123` fallback from CI scripts | DevOps | 30 min |
| W-01: Triage tampering | Add server-side auth before any write | Backend | 3 days |
| W-02/03: Auto PNG | Remove `_bp` auto-download; mask civil IDs in PNG | Frontend | 4 hours |
| W-07: PINs in admin | Replace PIN management with server-side flow | Backend | 1 day |
| W-08: Camera permission | Add `NSCameraUsageDescription` to `project.yml` | iOS | 30 min |

### Gate 2 — Required Within 2 Weeks of Launch

| Finding | Action | Estimate |
|---------|--------|----------|
| C-3, C-5: Anonymous auth | Named user authentication + RBAC | 1 week |
| W-04: Queue duplicate | Fix offline key reconciliation | 2 days |
| W-05: OCR safe default | Default OCR triage to 4 (Critical) | 1 hour |
| W-06: No expectant code | Add Code 0 (Expectant) and Code 5 (Deceased) | 1 day |
| W-10: ESI alignment | Remap codes to Kuwait ESI or add mapping doc | 1 day |
| W-11: Triage history | Add `code_ts` field and change log | 1 day |
| W-12: Toast persistence | Make error toasts require dismissal | 2 hours |
| V-09: Keystore | Use persistent keystore from secrets | 2 hours |
| C-7: Tests | Automated test suite | 2 weeks |

### Gate 3 — Required Within 60 Days

| Finding | Action |
|---------|--------|
| C-8: Compliance | HIPAA/Kuwait MOH compliance review with legal |
| W-13: Queue sessions | Bind queue to session; clear on logout |
| C-10: Retention | Implement data retention policy + auto-purge |
| C-6: Salt | Per-entry random salts + PBKDF2 |
| V-04: Gemini proxy | Cloud Function proxy for OCR |
| W-14: Undo delete | 5-second undo with queue cancellation |
| W-22: Glove mode | Larger touch targets option |

---

*End of Volume III. Read alongside EMERGENCY_HOSPITAL_AUDIT.md (Vol. I) and EMERGENCY_HOSPITAL_AUDIT_V2.md (Vol. II).*

*Three-volume total: 51 findings — 7 Critical, 14 High, 18 Medium, 12 Low.*
*System status: NOT CLEARED FOR HOSPITAL PRODUCTION USE until Gate 1 findings are resolved.*
