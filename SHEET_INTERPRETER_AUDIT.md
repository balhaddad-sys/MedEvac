# Google Sheet Interpreter — Audit Report & Improvement Recommendations

**Date:** 2026-03-21
**Scope:** `MAK_Registry/functions/index.js` — lines 436–870
**Functions audited:** `doSyncUnit`, `findMatch`, `parseSheetCSV`, `parseFlatTable`, `parseStructuredSheet`, normalization helpers, auto-sync scheduler

---

## Executive Summary

The sheet interpreter has a solid foundation (multi-signal matching, format detection, Arabic transliteration) but suffers from **critical bugs in duplicate detection and discharged-patient cleanup** that cause ghost records, false duplicates, and orphaned patients. This document catalogs every identified issue and provides concrete fix recommendations.

---

## CRITICAL BUGS

### BUG 1: No Within-Sheet Deduplication

**Location:** `doSyncUnit()` lines 778–810
**Severity:** Critical

The system only prevents duplicates by matching sheet patients against *database* patients. It never checks whether the **sheet itself** contains duplicate rows. If the Google Sheet has two rows for "Ahmed Hassan" (common with copy-paste errors, merged sections, or multiple tabs exported), both rows pass through and:

- The first row matches the DB record and updates it.
- The second row finds no unmatched DB record (the match was consumed by `matchedDbKeys`) and **creates a brand-new duplicate patient**.

**Fix:** Before the main sync loop, deduplicate `sheetPatients` by normalized `name|ward|room` key. Keep the last occurrence (most likely the updated version in a manually edited sheet).

```javascript
// Deduplicate sheet patients: keep last occurrence per normalized key
const seenSheet = new Map();
for (let i = 0; i < sheetPatients.length; i++) {
  const sp = sheetPatients[i];
  const key = normName(sp.name) + "|" + normWard(sp.ward) + "|" + normRoom(sp.room);
  seenSheet.set(key, i);
}
const dedupedPatients = [...seenSheet.values()].sort((a, b) => a - b).map(i => sheetPatients[i]);
```

---

### BUG 2: Discharged Patients Are Never Truly Removed

**Location:** `doSyncUnit()` lines 813–823
**Severity:** Critical

When a patient is removed from the sheet, they are marked `category: "Discharged"` but **remain in the database forever**. Over time, the `patients/{unit}` node accumulates hundreds of discharged records. This causes:

1. **Performance degradation** — every sync iterates all DB entries including discharged ones in `findMatch()`.
2. **False matches** — discharged patients with common names can steal matches from new patients (e.g., a new "Ahmed" matches the old discharged "Ahmed" instead of being created fresh).
3. **UI clutter** — unless the frontend aggressively filters, discharged patients pollute the list.

**Fix options:**

- **Option A (Recommended):** Filter out discharged patients from `dbEntries` before matching. Only match against active patients.
  ```javascript
  const dbEntries = Object.entries(dbData).filter(([, p]) => (p.category || "").toLowerCase() !== "discharged");
  ```

- **Option B:** After N days (e.g., 30), auto-archive discharged patients to a separate `archive/{unit}` node, removing them from the active patient pool entirely.

- **Option C:** Add a hard-delete mechanism — when a patient has been discharged for X days, remove the record. (Requires audit trail to be moved to the `audit` node first.)

---

### BUG 3: Re-admitted Patients May Not Reactivate Correctly

**Location:** `doSyncUnit()` lines 794–796
**Severity:** High

When a previously discharged patient reappears in the sheet, the code does:
```javascript
if ((upd.category || "").toLowerCase() === "discharged") {
  upd.category = sp.category || "Active";
  changed = true;
}
```

However, because `findMatch()` searches **all** DB entries (including discharged ones), and the matching algorithm gives a bonus to `prevSync` matches (+5 points), the system may:

1. Match the sheet patient to the **old discharged record** instead of a manually-created active record.
2. Reactivate the old record with stale data (old notes, old timestamps, old audit trail).

**Fix:** Prioritize active patients in matching. Add a penalty for discharged status:
```javascript
// In findMatch(), after computing score:
if ((pat.category || "").toLowerCase() === "discharged") {
  score -= 20; // Penalize discharged patients to prefer active matches
}
```

---

### BUG 4: Sync State Key Collisions

**Location:** `doSyncUnit()` line 780, `newSyncState` construction
**Severity:** High

The sync state key is built as:
```javascript
const spId = normName(sp.name) + "|" + normWard(sp.ward) + "|" + normRoom(sp.room);
```

If two different patients have the same normalized name, ward, and room (e.g., father and son named "Mohammed Ali" both in W5 Room 8 during a brief handover), only the **last one** is stored in `newSyncState`. The first patient's sync mapping is silently overwritten, and on the next sync cycle, that patient is incorrectly discharged.

**Fix:** Use a composite key that includes additional disambiguating info:
```javascript
const spId = normName(sp.name) + "|" + normWard(sp.ward) + "|" + normRoom(sp.room) + "|" + normName(sp.diagnosis || "");
```

Or better yet, use the **database key** as the primary identifier once matched:
```javascript
const spId = match ? match.key : (normName(sp.name) + "|" + normWard(sp.ward) + "|" + normRoom(sp.room));
```

---

## MATCHING ALGORITHM ISSUES

### ISSUE 5: Ward+Room Match Outranks Name Match — False Positives

**Location:** `findMatch()` lines 519–522
**Severity:** Medium

The matching signals use `else if` chaining. This means:
- If names don't match exactly but ward+room do, the score is 90.
- A completely different patient who happens to be in the same bed gets matched.

This is correct for **bed transfers** (same bed, new patient) but fails when:
- Patient A moves out of W5/R8 and Patient B moves in on the same day.
- The sheet reflects Patient B, but the DB still has Patient A.
- Patient B is matched to Patient A's record (score 90) instead of being created as a new patient.

**Fix:** Ward+Room should only be a **strong bonus**, not a standalone signal. Require at least *some* name overlap:
```javascript
// Signal 2: Ward + Room match WITH some name signal
else if (spWard && spRoom && dbWard && dbRoom && spWard === dbWard && spRoom === dbRoom) {
  // Only trust bed match if there's also partial name evidence
  const nameOverlap = spFirstName && dbFirstName && firstNameMatch(spFirstName, dbFirstName);
  score += nameOverlap ? 90 : 40; // 40 alone won't reach threshold
}
```

---

### ISSUE 6: Greedy Matching Order Dependency

**Location:** `doSyncUnit()` line 778
**Severity:** Medium

Sheet patients are matched in **array order** (first row first). The first sheet patient claims the best match, even if a later sheet patient would have been a *better* match for that DB record. This greedy approach can cause cascading mismatches.

**Example:**
- Sheet row 1: "Mohammed" (W5, R3) — scores 70 against DB "Mohammed Ali" (W5, R3)
- Sheet row 2: "Mohammed Ali" (W5, R3) — would score 100 against same DB record, but it's already claimed

Result: Row 1 steals the match; Row 2 becomes a duplicate.

**Fix:** Use a two-pass approach:
1. First pass: compute all scores (sheet × DB matrix).
2. Second pass: assign matches by highest score first (Hungarian algorithm or greedy-by-score).

```javascript
// Compute all match candidates
const candidates = [];
for (const sp of sheetPatients) {
  for (const [key, pat] of dbEntries) {
    const score = computeScore(sp, key, pat, prevSync);
    if (score >= 50) candidates.push({ sp, key, pat, score });
  }
}
// Sort by score descending, assign greedily
candidates.sort((a, b) => b.score - a.score);
const matchedDb = new Set();
const matchedSp = new Set();
for (const c of candidates) {
  if (matchedDb.has(c.key) || matchedSp.has(c.sp)) continue;
  matchedDb.add(c.key);
  matchedSp.add(c.sp);
  // ... process match
}
```

---

### ISSUE 7: No Civil ID Matching

**Location:** `findMatch()` — entire function
**Severity:** Medium

The flat table parser extracts `civil` (Civil ID) from the sheet, but `findMatch()` **never uses it** for matching. Civil ID is a unique national identifier — it should be the **strongest possible signal** (even stronger than name).

**Fix:**
```javascript
// Signal 0 (highest): Civil ID exact match (unique national identifier)
if (sp.civil && pat.civil && normName(sp.civil) === normName(pat.civil)) { score += 150; }
```

---

## PARSER ISSUES

### ISSUE 8: Structured Sheet Parser — Fragile Column Detection

**Location:** `parseStructuredSheet()` lines 657–666
**Severity:** Medium

The column detection logic has a bug on line 660:
```javascript
if (cl.includes("room") || cl.includes("ward") && cl.includes("/")) colRoom = j;
```

Due to operator precedence, this is parsed as:
```javascript
if (cl.includes("room") || (cl.includes("ward") && cl.includes("/"))) colRoom = j;
```

This means ANY column containing "room" is treated as the room column, which is correct — but any column containing just "ward" (without "/") will NOT be detected as the room column even if it should be. The intent was likely `(cl.includes("room") || cl.includes("ward")) && cl.includes("/")` or just separate conditions.

**Fix:**
```javascript
if (cl.includes("room") || cl.includes("bed") || (cl.includes("ward") && cl.includes("/"))) colRoom = j;
```

---

### ISSUE 9: Category Detection Overly Aggressive

**Location:** `parseStructuredSheet()` lines 670–671
**Severity:** Medium

```javascript
if (joined.includes("active")) { currentCategory = "Active"; continue; }
if (joined.includes("chronic")) { currentCategory = "Chronic"; continue; }
```

This skips **entire rows** if the joined text contains "active" or "chronic" anywhere. A patient named "Radioactive Waste Exposure" or diagnosis "Chronic kidney disease" would cause the row to be skipped entirely and misclassify all subsequent patients.

**Fix:** Be more specific about section header detection:
```javascript
const trimmedJoined = joined.replace(/,/g, "").trim();
if (/^(active\s*(patients?|list)?|male\s+list\s*\(active\)|female\s+list\s*\(active\))$/i.test(trimmedJoined)) {
  currentCategory = "Active"; continue;
}
if (/^(chronic\s*(patients?|list)?|male\s+list\s*\(chronic\)|female\s+list\s*\(chronic\))$/i.test(trimmedJoined)) {
  currentCategory = "Chronic"; continue;
}
```

---

### ISSUE 10: Ward Header Detection Misses Non-Standard Formats

**Location:** `parseStructuredSheet()` line 674
**Severity:** Low

The regex `/(ward\s*\d+|icu|er[\/\w]*)/i` doesn't handle:
- "CCU" (Coronary Care Unit)
- "NICU" (Neonatal ICU)
- "HDU" (High Dependency Unit)
- "OPD" (Outpatient Department)
- Arabic ward names

**Fix:** Expand the regex:
```javascript
const wardMatch = joined.match(/^[\s,]*(ward\s*\d+|icu|nicu|ccu|hdu|er[\/\w]*|opd)/i);
```

---

## PERFORMANCE ISSUES

### ISSUE 11: O(N*M) Matching Complexity

**Location:** `findMatch()` called in loop at line 781
**Severity:** Low (becomes Medium at scale)

For each sheet patient, `findMatch()` iterates all remaining DB entries. With N sheet patients and M DB patients, this is O(N*M) with expensive string operations (Levenshtein is O(L^2) per pair). At 200+ patients per unit, this could cause Cloud Function timeouts.

The `editDist()` function also uses O(m*n) space. For long names this is wasteful.

**Fix:**
- Use a single-row DP array for Levenshtein (reduces space from O(m*n) to O(n)).
- Pre-compute normalized names/wards/rooms once, not on every comparison.
- Build an index by normalized first name for fast candidate filtering.

---

### ISSUE 12: Sequential Database Writes

**Location:** `doSyncUnit()` line 825
**Severity:** Medium

```javascript
for (const [path, val] of Object.entries(writes)) { await db.ref(path).set(val); }
```

Each write is awaited individually. With 50 patients to update, this is 50 sequential round-trips to Firebase.

**Fix:** Use Firebase multi-path update (single atomic write):
```javascript
if (Object.keys(writes).length > 0) {
  await db.ref().update(writes);
}
```

This is faster, atomic (all-or-nothing), and reduces Firebase billing.

---

## RELIABILITY ISSUES

### ISSUE 13: No Retry Logic for Sheet Fetch

**Location:** `doSyncUnit()` line 761
**Severity:** Medium

```javascript
const res = await fetch(csvUrl);
if (!res.ok) throw new Error("Failed to fetch sheet for " + unit);
```

Google Sheets API can return transient 429 (rate limit) or 503 (temporary unavailability). The function fails and the entire sync for that unit is skipped until the next 5-minute cycle.

**Fix:**
```javascript
async function fetchWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    const res = await fetch(url);
    if (res.ok) return res;
    if (res.status === 429 || res.status >= 500) {
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
      continue;
    }
    throw new Error("Sheet fetch failed: HTTP " + res.status);
  }
  throw new Error("Sheet fetch failed after " + retries + " retries");
}
```

---

### ISSUE 14: No Validation of Sheet Content

**Location:** `parseSheetCSV()` / `doSyncUnit()`
**Severity:** Medium

If the Google Sheet URL points to a redirect page (e.g., login required, sheet deleted), the CSV will contain HTML. The parser will return 0 patients, and `doSyncUnit` will **discharge every patient in the unit** because none match the (empty) sheet.

**Fix:** Add a sanity check:
```javascript
const sheetPatients = parseSheetCSV(csv);

// Safety check: if sheet returns 0 patients but we had patients before, something is wrong
if (sheetPatients.length === 0 && Object.keys(prevSync).length > 0) {
  console.warn("Sheet returned 0 patients for " + unit + " but had " + Object.keys(prevSync).length + " previously. Skipping to prevent mass discharge.");
  return { added: 0, updated: 0, discharged: 0, unchanged: 0, total: 0, skipped: true, reason: "empty_sheet_safety" };
}

// Also check for HTML content (login page, error page)
if (csv.trim().startsWith("<!") || csv.trim().startsWith("<html")) {
  throw new Error("Sheet returned HTML instead of CSV — check sharing permissions");
}
```

---

### ISSUE 15: Auto-Sync Silently Swallows Errors

**Location:** `autoSyncSheets` (lines 839–870)
**Severity:** Low

Errors in auto-sync are logged to console but not tracked in any queryable way. If a unit's sheet breaks, the admin has no way to know until they manually check.

**Fix:** Write sync errors to the database:
```javascript
catch (e) {
  console.error("Auto-sync error for " + unit + ":", e);
  await db.ref("config/sheetErrors/" + unit).set({
    error: (e.message || "unknown").slice(0, 500),
    ts: Date.now(),
  });
}
```

---

## SUMMARY TABLE

| # | Issue | Severity | Type | Estimated Effort |
|---|-------|----------|------|-----------------|
| 1 | No within-sheet deduplication | Critical | Bug | Small (10 lines) |
| 2 | Discharged patients never removed from matching pool | Critical | Bug | Small (1 line filter) |
| 3 | Re-admitted patients match stale discharged records | High | Bug | Small (2 lines) |
| 4 | Sync state key collisions | High | Bug | Small (1 line change) |
| 5 | Ward+Room match without name verification | Medium | Logic | Small (5 lines) |
| 6 | Greedy matching causes order-dependent mismatches | Medium | Algorithm | Medium (30 lines) |
| 7 | Civil ID never used for matching | Medium | Missing feature | Small (2 lines) |
| 8 | Operator precedence bug in column detection | Medium | Bug | Trivial (1 line) |
| 9 | Category detection skips patient rows | Medium | Bug | Small (5 lines) |
| 10 | Missing ward types (CCU, NICU, HDU) | Low | Missing feature | Trivial (1 line) |
| 11 | O(N*M) matching performance | Low | Performance | Medium (20 lines) |
| 12 | Sequential database writes | Medium | Performance | Trivial (2 lines) |
| 13 | No retry on sheet fetch | Medium | Reliability | Small (10 lines) |
| 14 | Empty sheet causes mass discharge | Medium | Safety | Small (5 lines) |
| 15 | Silent auto-sync errors | Low | Observability | Small (5 lines) |

---

## RECOMMENDED IMPLEMENTATION ORDER

### Phase 1 — Stop the Bleeding (Critical Fixes)
1. **Bug 14** — Empty sheet safety check (prevents mass discharge disasters)
2. **Bug 2** — Filter discharged patients from matching pool
3. **Bug 1** — Within-sheet deduplication
4. **Bug 12** — Multi-path atomic writes (easy win, prevents partial sync states)

### Phase 2 — Correctness
5. **Bug 3** — Discharged patient penalty in matching
6. **Bug 4** — Better sync state keys
7. **Bug 5** — Ward+Room requires name evidence
8. **Bug 7** — Civil ID matching
9. **Bug 8** — Operator precedence fix

### Phase 3 — Robustness
10. **Bug 9** — Stricter category header detection
11. **Bug 13** — Retry logic for sheet fetch
12. **Bug 15** — Persist sync errors
13. **Bug 10** — Expanded ward types

### Phase 4 — Scale
14. **Bug 6** — Score-ranked matching (Hungarian-lite)
15. **Bug 11** — Matching performance optimization

---

## ARCHITECTURAL RECOMMENDATION

Consider adding a **dry-run mode** to `doSyncUnit()` that computes all matches and changes but writes nothing to the database. This would:
- Allow admins to preview sync results before committing.
- Enable automated testing of the matching algorithm.
- Provide a safety net for large-scale changes.

```javascript
async function doSyncUnit(unit, uidForAudit, { dryRun = false } = {}) {
  // ... same logic ...
  if (!dryRun) {
    await db.ref().update(writes);
    await db.ref("config/sheetSync/" + unit).set(newSyncState);
  }
  return { added, updated, discharged, unchanged, total: sheetPatients.length, dryRun, writes };
}
```
