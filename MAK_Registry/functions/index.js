const functions = require("firebase-functions/v1");
const { initializeApp } = require("firebase-admin/app");
const { getDatabase } = require("firebase-admin/database");

initializeApp();
const db = getDatabase();

// Rate limiting: track failed attempts per IP
const failMap = new Map();
const FAIL_LIMIT = 5;
const LOCK_MS = 60000;

function checkRateLimit(ip) {
  const entry = failMap.get(ip);
  if (!entry) return true;
  if (Date.now() > entry.lockUntil) {
    if (Date.now() - entry.lastFail > 300000) failMap.delete(ip);
    return true;
  }
  return false;
}

function recordFail(ip) {
  const entry = failMap.get(ip) || { count: 0, lockUntil: 0, lastFail: 0 };
  entry.count++;
  entry.lastFail = Date.now();
  if (entry.count >= FAIL_LIMIT) {
    entry.lockUntil = Date.now() + LOCK_MS * Math.min(entry.count - FAIL_LIMIT + 1, 5);
  }
  failMap.set(ip, entry);
}

function resetFails(ip) {
  failMap.delete(ip);
}

// PBKDF2 verification using Node crypto
const crypto = require("crypto");

function verifyPin(pin, stored) {
  if (!stored || !pin) return false;
  // PBKDF2 format: "salt$hash"
  if (stored.includes("$")) {
    const [salt, hash] = stored.split("$");
    const derived = crypto.pbkdf2Sync(pin, salt, 100000, 32, "sha256").toString("hex");
    return crypto.timingSafeEqual(Buffer.from(derived, "hex"), Buffer.from(hash, "hex"));
  }
  // Legacy SHA-256 with "_mak_salt"
  if (stored.length === 64) {
    const h = crypto.createHash("sha256").update(pin + "_mak_salt").digest("hex");
    return crypto.timingSafeEqual(Buffer.from(h, "hex"), Buffer.from(stored, "hex"));
  }
  // Plaintext during migration (4-6 chars)
  if (stored.length >= 4 && stored.length <= 6) {
    return pin === stored;
  }
  return false;
}

exports.verifyPin = functions.region("europe-west1").https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Must be authenticated");
  }

  const { unit, pin } = data;
  const validUnits = /^(A_M|A_F|B_M|B_F|C_M|C_F|D_M|D_F|E_M|E_F|ADMIN)$/;
  if (!unit || !validUnits.test(unit)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid unit");
  }
  if (!pin || typeof pin !== "string" || pin.length !== 4) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid PIN");
  }

  // Rate limit by both IP and UID — prevents bypass via new anonymous accounts
  const ip = context.rawRequest?.ip || "unknown";
  const uid = context.auth.uid || "unknown";
  if (!checkRateLimit(ip) || !checkRateLimit("uid:" + uid)) {
    throw new functions.https.HttpsError("resource-exhausted", "Too many attempts. Try again later.");
  }

  // Read stored PIN from database
  const snap = await db.ref("pins/" + unit).once("value");
  const stored = snap.val();
  if (!stored) {
    throw new functions.https.HttpsError("not-found", "PIN not configured for this unit");
  }

  const match = verifyPin(pin, stored);
  if (!match) {
    recordFail(ip);
    recordFail("uid:" + uid);
    await db.ref("audit").push({
      action: "login_fail",
      unit,
      ts: Date.now(),
      uid: uid,
    });
    throw new functions.https.HttpsError("permission-denied", "Wrong PIN");
  }

  resetFails(ip);
  resetFails("uid:" + uid);
  await db.ref("audit").push({
    action: "login",
    unit,
    ts: Date.now(),
    uid: uid,
  });

  return { success: true, unit };
});

// Set/update a PIN (admin only — must verify ADMIN PIN first)
exports.setPin = functions.region("europe-west1").https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Must be authenticated");
  }

  const { adminPin, unit, newPin } = data;
  const validUnits = /^(A_M|A_F|B_M|B_F|C_M|C_F|D_M|D_F|E_M|E_F|ADMIN)$/;
  if (!unit || !validUnits.test(unit)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid unit");
  }
  if (!newPin || typeof newPin !== "string" || newPin.length !== 4) {
    throw new functions.https.HttpsError("invalid-argument", "PIN must be 4 digits");
  }
  if (!adminPin || typeof adminPin !== "string") {
    throw new functions.https.HttpsError("invalid-argument", "Admin PIN required");
  }

  // Verify admin PIN
  const adminSnap = await db.ref("pins/ADMIN").once("value");
  const adminStored = adminSnap.val();
  if (!adminStored || !verifyPin(adminPin, adminStored)) {
    throw new functions.https.HttpsError("permission-denied", "Invalid admin PIN");
  }

  // Hash the new PIN with PBKDF2
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(newPin, salt, 100000, 32, "sha256").toString("hex");
  const stored = salt + "$" + hash;

  await db.ref("pins/" + unit).set(stored);
  await db.ref("audit").push({
    action: "pin_change",
    unit,
    ts: Date.now(),
    uid: context.auth.uid || "anon",
  });

  return { success: true };
});

// Check if a unit has a PIN configured (doesn't reveal the PIN)
exports.hasPins = functions.region("europe-west1").https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Must be authenticated");
  }

  const snap = await db.ref("pins").once("value");
  const pins = snap.val() || {};
  const result = {};
  for (const key of Object.keys(pins)) {
    result[key] = true;
  }
  return result;
});

// Audit log: read recent audit entries (admin only — verifies ADMIN PIN)
exports.getAuditLog = functions.region("europe-west1").https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Must be authenticated");
  }

  const { adminPin, limit: reqLimit } = data;
  if (!adminPin || typeof adminPin !== "string") {
    throw new functions.https.HttpsError("invalid-argument", "Admin PIN required");
  }

  // Verify admin PIN
  const adminSnap = await db.ref("pins/ADMIN").once("value");
  const adminStored = adminSnap.val();
  if (!adminStored || !verifyPin(adminPin, adminStored)) {
    throw new functions.https.HttpsError("permission-denied", "Invalid admin PIN");
  }

  const entryLimit = Math.min(Math.max(parseInt(reqLimit) || 100, 10), 500);
  const snap = await db.ref("audit").orderByChild("ts").limitToLast(entryLimit).once("value");
  const entries = [];
  snap.forEach(child => {
    entries.push({ _k: child.key, ...child.val() });
  });
  // Sort newest first
  entries.sort((a, b) => (b.ts || 0) - (a.ts || 0));
  return { entries };
});

// OCR: extract patient data from images via Claude API (key stays server-side)
const ocrRateMap = new Map();
const OCR_LIMIT = 10; // max 10 OCR calls per minute per user
const OCR_WINDOW = 60000;

exports.ocrExtract = functions.region("europe-west1").https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Must be authenticated");
  }

  // Rate limit per user
  const uid = context.auth.uid;
  const now = Date.now();
  const entry = ocrRateMap.get(uid) || { count: 0, windowStart: now };
  if (now - entry.windowStart > OCR_WINDOW) {
    entry.count = 0;
    entry.windowStart = now;
  }
  entry.count++;
  ocrRateMap.set(uid, entry);
  if (entry.count > OCR_LIMIT) {
    throw new functions.https.HttpsError("resource-exhausted", "Too many OCR requests. Wait a minute.");
  }

  // Validate input
  const { images } = data;
  if (!images || !Array.isArray(images) || images.length === 0 || images.length > 5) {
    throw new functions.https.HttpsError("invalid-argument", "Provide 1-5 images");
  }
  for (const img of images) {
    if (!img.data || !img.mime || typeof img.data !== "string" || typeof img.mime !== "string") {
      throw new functions.https.HttpsError("invalid-argument", "Invalid image format");
    }
    if (!img.mime.startsWith("image/")) {
      throw new functions.https.HttpsError("invalid-argument", "Only image files allowed");
    }
    // Limit base64 size (~10MB per image)
    if (img.data.length > 14000000) {
      throw new functions.https.HttpsError("invalid-argument", "Image too large (max 10MB)");
    }
  }

  // Get API key from database
  const keySnap = await db.ref("config/claudeKey").once("value");
  const apiKey = keySnap.val();
  if (!apiKey) {
    throw new functions.https.HttpsError("failed-precondition", "OCR not configured");
  }

  // Build Claude API request
  const content = [];
  for (const img of images) {
    content.push({ type: "image", source: { type: "base64", media_type: img.mime, data: img.data } });
  }
  content.push({ type: "text", text: 'Extract ALL patient information from these images. Output ONLY valid JSON — no explanations, no markdown, no text before or after. Format: [{"name":"Full Name","civil":"Civil ID","nat":"Nationality","ward":"Ward (e.g. W21)","room":"Room (e.g. R8)","code":1,"notes":""}]. code: 1=green, 2=yellow, 3=critical/red. Unknown fields="". No patients=[].' });

  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 4096,
        system: "You are a data extraction tool. You MUST respond with ONLY a JSON array. Never include any text, explanation, or markdown — just raw JSON. If you cannot find patient data, respond with [].",
        messages: [
          { role: "user", content },
          { role: "assistant", content: [{ type: "text", text: "[" }] },
        ],
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error("Claude API error:", res.status, errText);
      throw new functions.https.HttpsError("internal", "OCR service error");
    }

    const result = await res.json();
    const raw = "[" + (result.content?.[0]?.text || "]");
    const cleaned = raw.replace(/```json|```/g, "").trim();
    const jsonMatch = cleaned.match(/\[[\s\S]*\]/);
    if (!jsonMatch) {
      return { patients: [] };
    }

    const patients = JSON.parse(jsonMatch[0]);
    if (!Array.isArray(patients)) return { patients: [] };

    // Sanitize output
    const safe = patients.map(p => ({
      name: String(p.name || "").slice(0, 200),
      civil: String(p.civil || "").slice(0, 20),
      nat: String(p.nat || "").slice(0, 50),
      ward: String(p.ward || "").slice(0, 30),
      room: String(p.room || "").slice(0, 30),
      code: Math.max(1, Math.min(3, parseInt(p.code) || 2)),
      notes: String(p.notes || "").slice(0, 500),
    }));

    await db.ref("audit").push({
      action: "ocr_extract",
      unit: "ADMIN",
      ts: Date.now(),
      uid: context.auth.uid,
      count: safe.length,
    });

    return { patients: safe };
  } catch (e) {
    if (e instanceof functions.https.HttpsError) throw e;
    console.error("OCR error:", e);
    throw new functions.https.HttpsError("internal", "OCR processing failed");
  }
});

// Set minimum app version for force-update (admin-only)
exports.setMinVersion = functions.region("europe-west1").https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError("unauthenticated", "Must be authenticated");
  const { adminPin, version, storeUrl } = data;
  if (!adminPin || typeof adminPin !== "string") throw new functions.https.HttpsError("invalid-argument", "Admin PIN required");
  const adminSnap = await db.ref("pins/ADMIN").once("value");
  const adminStored = adminSnap.val();
  if (!adminStored || !verifyPin(adminPin, adminStored)) throw new functions.https.HttpsError("permission-denied", "Invalid admin PIN");
  if (version) await db.ref("config/minAppVersion").set(version);
  if (storeUrl) await db.ref("config/appStoreURL").set(storeUrl);
  return { success: true };
});

// Google Sheets: save a sheet URL for a unit (admin-only)
exports.setSheetUrl = functions.region("europe-west1").https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Must be authenticated");
  }
  const { adminPin, unit, url } = data;
  if (!adminPin || typeof adminPin !== "string") {
    throw new functions.https.HttpsError("invalid-argument", "Admin PIN required");
  }
  const validUnits = /^[A-E]_(M|F)$/;
  if (!unit || !validUnits.test(unit)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid unit (e.g. A_M, A_F)");
  }
  // Verify admin PIN
  const adminSnap = await db.ref("pins/ADMIN").once("value");
  const adminStored = adminSnap.val();
  if (!adminStored || !verifyPin(adminPin, adminStored)) {
    throw new functions.https.HttpsError("permission-denied", "Invalid admin PIN");
  }
  // Save or clear the URL
  if (!url || typeof url !== "string" || !url.trim()) {
    await db.ref("config/sheets/" + unit).remove();
  } else {
    if (url.length > 500) {
      throw new functions.https.HttpsError("invalid-argument", "URL too long");
    }
    await db.ref("config/sheets/" + unit).set(url.trim());
  }
  await db.ref("audit").push({
    action: "sheet_url_change",
    unit,
    ts: Date.now(),
    uid: context.auth.uid || "anon",
    detail: url ? "set" : "cleared",
  });
  return { success: true };
});

// Google Sheets: get all configured sheet URLs (admin-only)
exports.getSheetUrls = functions.region("europe-west1").https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Must be authenticated");
  }
  const { adminPin } = data;
  if (!adminPin || typeof adminPin !== "string") {
    throw new functions.https.HttpsError("invalid-argument", "Admin PIN required");
  }
  const adminSnap = await db.ref("pins/ADMIN").once("value");
  const adminStored = adminSnap.val();
  if (!adminStored || !verifyPin(adminPin, adminStored)) {
    throw new functions.https.HttpsError("permission-denied", "Invalid admin PIN");
  }
  const snap = await db.ref("config/sheets").once("value");
  return snap.val() || {};
});

// Google Sheets: fetch sheet data and return parsed patients (admin-only)
exports.fetchSheet = functions.region("europe-west1").https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Must be authenticated");
  }
  const { adminPin, unit } = data;
  if (!adminPin || typeof adminPin !== "string") {
    throw new functions.https.HttpsError("invalid-argument", "Admin PIN required");
  }
  const validUnits = /^[A-E]_(M|F)$/;
  if (!unit || !validUnits.test(unit)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid unit (e.g. A_M, A_F)");
  }
  // Verify admin PIN
  const adminSnap = await db.ref("pins/ADMIN").once("value");
  const adminStored = adminSnap.val();
  if (!adminStored || !verifyPin(adminPin, adminStored)) {
    throw new functions.https.HttpsError("permission-denied", "Invalid admin PIN");
  }
  // Get sheet URL
  const urlSnap = await db.ref("config/sheets/" + unit).once("value");
  const sheetUrl = urlSnap.val();
  if (!sheetUrl) {
    throw new functions.https.HttpsError("not-found", "No sheet configured for unit " + unit);
  }
  // Extract sheet ID from URL
  const m = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9_-]+)/);
  if (!m) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid Google Sheets URL");
  }
  const sheetId = m[1];
  // Extract gid (sheet tab) if present
  const gidMatch = sheetUrl.match(/gid=(\d+)/);
  const gid = gidMatch ? gidMatch[1] : "0";
  const csvUrl = "https://docs.google.com/spreadsheets/d/" + sheetId + "/export?format=csv&gid=" + gid;
  try {
    const res = await fetch(csvUrl);
    if (!res.ok) {
      throw new functions.https.HttpsError("internal", "Failed to fetch sheet (is it shared as public/anyone with link?)");
    }
    const csv = await res.text();
    const patients = parseSheetCSV(csv);
    return { patients };
  } catch (e) {
    if (e instanceof functions.https.HttpsError) throw e;
    console.error("Sheet fetch error:", e);
    throw new functions.https.HttpsError("internal", "Failed to process sheet");
  }
});

// Google Sheets: intelligent sync — adds new, updates changed, discharges removed
// Normalize names for matching: lowercase, strip non-alphanumeric (keep Arabic), collapse spaces
function normName(n) {
  return (n || "").toLowerCase().replace(/[^a-z0-9\u0600-\u06FF]/g, " ").replace(/\s+/g, " ").trim();
}
// Normalize room/bed: strip "R" prefix, normalize separators "R 11-1" -> "11-1", "R8" -> "8"
function normRoom(r) {
  return (r || "").replace(/^R\s*/i, "").replace(/\s+/g, "").trim();
}
// Normalize ward: "W 5" -> "W5", "ward 5" -> "W5", "جناح 5" -> "W5"
function normWard(w) {
  const m = (w || "").match(/(?:W(?:ard)?|جناح)\s*(\d+)/i);
  if (m) return "W" + m[1];
  // Map Arabic ward names to standard codes
  if ((w || "").includes("عناية مركزة")) return "ICU";
  if ((w || "").includes("طوارئ")) return "ER";
  return (w || "").replace(/\s+/g, "").toUpperCase();
}
// General-purpose Arabic → Latin transliteration (phonetic approximation)
// Converts any Arabic text to a Latin equivalent for cross-script fuzzy matching
// Note: و and ي are context-dependent vowel/consonant letters
const ar2latMap = {
  "ا":"a","أ":"a","إ":"i","آ":"aa","ب":"b","ت":"t","ث":"th","ج":"j","ح":"h","خ":"kh",
  "د":"d","ذ":"dh","ر":"r","ز":"z","س":"s","ش":"sh","ص":"s","ض":"d","ط":"t","ظ":"z",
  "ع":"a","غ":"gh","ف":"f","ق":"q","ك":"k","ل":"l","م":"m","ن":"n","ه":"h",
  "ى":"a","ة":"a","ء":"","ئ":"e","ؤ":"o",
  // Combined forms
  "لا":"la","لأ":"la","لإ":"li","لآ":"laa",
};
// و and ي are handled specially: they can be consonants (w/y) or vowels (o,u/i,ee)
const arConsonants = new Set("بتثجحخدذرزسشصضطظعغفقكلمنه");
function arabicToLatin(s) {
  if (!s) return "";
  let out = "";
  for (let i = 0; i < s.length; i++) {
    // Check two-char combos first (لا etc.)
    const two = s[i] + (s[i + 1] || "");
    if (ar2latMap[two]) { out += ar2latMap[two]; i++; continue; }
    const ch = s[i];
    if (ch === "و") {
      // و after consonant = "o"/"u" vowel; at start or before consonant = "w"
      const prev = s[i - 1];
      out += (prev && arConsonants.has(prev)) ? "o" : "w";
    } else if (ch === "ي") {
      // ي after consonant = "i"/"ee" vowel; at start or before consonant = "y"
      const prev = s[i - 1];
      out += (prev && arConsonants.has(prev)) ? "i" : "y";
    } else if (ar2latMap[ch] !== undefined) { out += ar2latMap[ch]; }
    else if (/[a-z0-9]/i.test(ch)) { out += ch.toLowerCase(); }
    else if (ch === " ") { out += " "; }
    // Skip diacritics (tashkeel) and other marks
  }
  return out.replace(/\s+/g, " ").trim();
}

// Check if a string contains Arabic characters
function hasArabic(s) { return /[\u0600-\u06FF]/.test(s || ""); }

// Convert name to Latin for cross-script comparison
function toLatin(s) {
  if (!s) return "";
  return hasArabic(s) ? arabicToLatin(s) : s.toLowerCase();
}

// Strip vowels for consonant-skeleton comparison (Arabic doesn't write most vowels)
// "mohammed" -> "mhmmd", "mhmd" -> "mhmd" — much closer match
function stripVowels(s) {
  return (s || "").replace(/[aeiou]/gi, "");
}

// Levenshtein edit distance (single-row DP — O(n) space instead of O(m*n))
function editDist(a, b) {
  if (!a) return (b || "").length;
  if (!b) return a.length;
  const m = a.length, n = b.length;
  let prev = new Array(n + 1);
  let curr = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      curr[j] = a[i - 1] === b[j - 1]
        ? prev[j - 1]
        : 1 + Math.min(prev[j], curr[j - 1], prev[j - 1]);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

// Similarity ratio: 0-1 (1 = identical)
function nameSimilarity(a, b) {
  if (!a || !b) return 0;
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;
  return 1 - editDist(a, b) / maxLen;
}

// Check if two first names are fuzzy-equivalent
function firstNameMatch(a, b) {
  if (!a || !b) return false;
  if (a === b) return true;
  // Direct fuzzy: allow 1-2 char difference for names >= 4 chars
  const dist = editDist(a, b);
  const maxLen = Math.max(a.length, b.length);
  if (maxLen >= 4 && dist <= 2) return true;
  if (maxLen >= 3 && dist <= 1) return true;
  // One contains the other (e.g. "mohammad" contains "mohamad")
  if (a.includes(b) || b.includes(a)) return true;
  return false;
}

// Multi-signal patient matching: returns the best DB match for a sheet patient
function findMatch(sp, dbEntries, prevSync) {
  const spName = normName(sp.name);
  const spWard = normWard(sp.ward);
  const spRoom = normRoom(sp.room);
  const spFirstName = spName.split(" ")[0];

  let bestMatch = null;
  let bestScore = 0;

  for (const [key, pat] of dbEntries) {
    const dbName = normName(pat.name);
    const dbWard = normWard(pat.ward);
    const dbRoom = normRoom(pat.room);
    const dbFirstName = dbName.split(" ")[0];
    let score = 0;

    // Signal 0: Civil ID exact match (unique national identifier — strongest possible signal)
    if (sp.civil && pat.civil && sp.civil.trim() && pat.civil.trim() && sp.civil.trim() === pat.civil.trim()) { score += 150; }

    // Cross-script support: convert both names to Latin for comparison
    const spLatin = toLatin(spName);
    const dbLatin = toLatin(dbName);
    const spFirstLatin = spLatin.split(" ")[0];
    const dbFirstLatin = dbLatin.split(" ")[0];

    // Signal 1: Exact normalized name match (same script)
    if (spName && dbName && spName === dbName) { score += 100; }
    // Signal 1b: Exact match after cross-script transliteration (e.g. "هاراكامان" == "harakaman")
    else if (spLatin && dbLatin && spLatin === dbLatin) { score += 100; }
    // Signal 2: Ward + Room match — only strong if there's also partial name evidence
    else if (spWard && spRoom && dbWard && dbRoom && spWard === dbWard && spRoom === dbRoom) {
      const nameOverlap = spFirstLatin && dbFirstLatin && firstNameMatch(spFirstLatin, dbFirstLatin);
      score += nameOverlap ? 90 : 40; // 40 alone won't reach threshold of 50
    }
    // Signal 3: One name contains the other (partial match, cross-script)
    else if (spLatin && dbLatin && (dbLatin.includes(spLatin) || spLatin.includes(dbLatin))) { score += 70; }
    // Signal 4: Fuzzy full-name similarity (cross-script, handles typos)
    // Use lower threshold (0.55) when comparing across scripts (transliteration is lossy)
    else if (spLatin && dbLatin) {
      const sim = nameSimilarity(spLatin, dbLatin);
      const crossScript = hasArabic(spName) !== hasArabic(dbName);
      if (sim >= (crossScript ? 0.55 : 0.7)) { score += 65; }
    }
    // Signal 5: First name fuzzy match (cross-script)
    else if (spFirstLatin && dbFirstLatin && firstNameMatch(spFirstLatin, dbFirstLatin)) { score += 55; }
    // Signal 6: Consonant-skeleton match (handles Arabic vowel dropping: "mohammed"→"mhmmd" ≈ "mhmd"←"محمد")
    else if (spLatin && dbLatin) {
      const spCons = stripVowels(spLatin), dbCons = stripVowels(dbLatin);
      if (spCons && dbCons && spCons.length >= 2 && dbCons.length >= 2 && nameSimilarity(spCons, dbCons) >= 0.65) { score += 60; }
    }

    // Bonus: ward matches on top of name signal
    if (score > 0 && spWard && dbWard && spWard === dbWard) { score += 15; }
    // Bonus: room matches on top of other signals
    if (score > 0 && spRoom && dbRoom && spRoom === dbRoom) { score += 10; }
    // Bonus: diagnosis similarity (extra confidence, cross-script)
    if (score > 0 && sp.diagnosis && pat.diagnosis) {
      const spDx = toLatin(normName(sp.diagnosis)), dbDx = toLatin(normName(pat.diagnosis));
      if (spDx && dbDx && (spDx.includes(dbDx) || dbDx.includes(spDx) || nameSimilarity(spDx, dbDx) >= 0.6)) { score += 10; }
    }
    // Bonus: was previously synced to this key
    if (score > 0) {
      const prevKey = Object.values(prevSync).find(v => v === key);
      if (prevKey) score += 5;
    }

    if (score > bestScore) {
      bestScore = score;
      bestMatch = { key, pat, score };
    }
  }

  // Require minimum confidence to match
  return bestScore >= 50 ? bestMatch : null;
}

exports.syncSheet = functions.region("europe-west1").https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Must be authenticated");
  }
  const { adminPin, unit } = data;
  if (!adminPin || typeof adminPin !== "string") {
    throw new functions.https.HttpsError("invalid-argument", "Admin PIN required");
  }
  const validUnits = /^[A-E]_(M|F)$/;
  if (!unit || !validUnits.test(unit)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid unit");
  }
  const adminSnap = await db.ref("pins/ADMIN").once("value");
  const adminStored = adminSnap.val();
  if (!adminStored || !verifyPin(adminPin, adminStored)) {
    throw new functions.https.HttpsError("permission-denied", "Invalid admin PIN");
  }
  try {
    const result = await doSyncUnit(unit, context.auth.uid || "anon");
    if (!result) throw new functions.https.HttpsError("not-found", "No sheet configured for unit " + unit);
    return result;
  } catch (e) {
    if (e instanceof functions.https.HttpsError) throw e;
    console.error("Sheet sync error:", e);
    throw new functions.https.HttpsError("internal", "Sync failed: " + (e.message || "unknown error"));
  }
});

// Smart sheet parser: handles structured sheets with ward headers, sections, etc.
// Supports both English and Arabic headers/labels.
// Supports two formats:
//   1. Flat table: first row has headers (Name, Civil ID, Ward, etc.)
//   2. Structured: ward headers ("Ward 20" / "جناح 20"), section headers,
//      with columns: Room/Ward | Patient name | Diagnosis | ? | Assigned Doctor | Status
function parseSheetCSV(csv) {
  const lines = csv.split("\n").filter(l => l.trim());
  if (lines.length < 2) return [];

  // Check if this is a flat table (first row looks like headers)
  const firstRow = parseCSVRow(lines[0]).map(h => h.toLowerCase().trim());
  const headerKeywords = [
    "name", "patient", "civil", "ward", "room", "diagnosis", "doctor", "code", "severity",
    "اسم", "مريض", "مدني", "جناح", "غرفة", "سرير", "تشخيص", "طبيب", "دكتور", "حالة",
  ];
  const headerMatches = firstRow.filter(h => headerKeywords.some(k => h.includes(k))).length;

  if (headerMatches >= 2) {
    // Flat table format
    return parseFlatTable(lines, firstRow);
  }

  // Structured format: scan for ward headers and patient rows
  return parseStructuredSheet(lines);
}

// Helper: find first matching header value from a row object
function findCol(row, keys) {
  for (const k of keys) { if (row[k]) return row[k]; }
  return "";
}

function parseFlatTable(lines, headers) {
  const patients = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = parseCSVRow(lines[i]);
    const row = {};
    headers.forEach((h, j) => { row[h] = (cols[j] || "").trim(); });
    const name = findCol(row, [
      "name", "full name", "patient name", "patient",
      "الاسم", "اسم المريض", "اسم", "مريض", "الاسم الكامل",
    ]);
    const civil = findCol(row, [
      "civil", "civil id", "civilid", "id",
      "الرقم المدني", "رقم مدني", "مدني", "الهوية",
    ]);
    const nat = findCol(row, [
      "nat", "nationality", "nation",
      "الجنسية", "جنسية",
    ]);
    const ward = findCol(row, [
      "ward", "ward no", "ward number",
      "جناح", "الجناح", "رقم الجناح",
    ]);
    const room = findCol(row, [
      "room", "room no", "bed", "room / bed",
      "غرفة", "الغرفة", "رقم الغرفة", "سرير", "السرير",
    ]);
    const code = parseInt(findCol(row, [
      "code", "severity", "severity code",
      "كود", "الشدة", "درجة الخطورة",
    ]) || "2") || 2;
    const notes = findCol(row, [
      "notes", "note",
      "ملاحظات", "ملاحظة",
    ]);
    const doctor = findCol(row, [
      "doctor", "attending doctor", "dr",
      "طبيب", "الطبيب", "دكتور", "الدكتور", "الطبيب المعالج",
    ]);
    const diagnosis = findCol(row, [
      "diagnosis", "dx",
      "تشخيص", "التشخيص",
    ]);
    if (!name) continue;
    patients.push({
      name: name.slice(0, 200), civil: civil.slice(0, 20), nat: nat.slice(0, 50),
      ward: ward.slice(0, 30), room: room.slice(0, 30),
      code: Math.max(1, Math.min(3, code)),
      notes: notes.slice(0, 500), doctor: doctor.slice(0, 100), diagnosis: diagnosis.slice(0, 200),
    });
  }
  return patients;
}

function parseStructuredSheet(lines) {
  const patients = [];
  let currentWard = "";
  let currentCategory = "Active"; // Active or Chronic
  // Column mapping for structured sheets:
  // A=Room/Bed, B=Patient name, C=Diagnosis, D=?(empty), E=Assigned Doctor, F=Status
  // Detect column layout from header row
  let colRoom = 0, colName = 1, colDiagnosis = 2, colDoctor = 4, colStatus = 5;

  for (let i = 0; i < lines.length; i++) {
    const cols = parseCSVRow(lines[i]);
    const joined = cols.join(" ").trim().toLowerCase();

    // Detect header row to map columns (English + Arabic)
    if (joined.includes("patient name") || joined.includes("patient_name") || joined.includes("اسم المريض") || joined.includes("اسم")) {
      cols.forEach((c, j) => {
        const cl = c.toLowerCase().trim();
        if (cl.includes("room") || cl.includes("bed") || cl.includes("غرفة") || cl.includes("سرير") || (cl.includes("ward") && cl.includes("/"))) colRoom = j;
        else if (cl.includes("patient") || cl.includes("مريض") || cl.includes("اسم")) colName = j;
        else if (cl.includes("diagnosis") || cl === "dx" || cl.includes("تشخيص")) colDiagnosis = j;
        else if (cl.includes("doctor") || cl === "dr" || cl.includes("طبيب") || cl.includes("دكتور")) colDoctor = j;
        else if (cl.includes("status") || cl.includes("حالة") || cl.includes("الحالة")) colStatus = j;
      });
      continue;
    }

    // Detect section headers: "active" or "chronic" — strict matching to avoid false positives
    // Strip commas, parentheses, brackets for clean matching
    const trimmedJoined = joined.replace(/[,\(\)\[\]]/g, "").trim();
    if (/^(active\s*(patients?|list)?|(?:male|female)\s+list\s*active|active\s+list)$/i.test(trimmedJoined)) { currentCategory = "Active"; continue; }
    if (/^(chronic\s*(patients?|list)?|(?:male|female)\s+list\s*chronic|chronic\s+list)$/i.test(trimmedJoined)) { currentCategory = "Chronic"; continue; }
    // Arabic section headers: نشط/حاد (active), مزمن (chronic)
    if (/^(نشط|حاد|مرضى نشطين|قائمة نشطة|مرضى حادين)$/.test(trimmedJoined)) { currentCategory = "Active"; continue; }
    if (/^(مزمن|مرضى مزمنين|قائمة مزمنة)$/.test(trimmedJoined)) { currentCategory = "Chronic"; continue; }

    // Detect ward header: "Ward 20", "جناح 20", "ICU", "ER/Unassigned"
    const wardMatch = joined.match(/^[\s,]*(ward\s*\d+|جناح\s*\d+|icu|nicu|ccu|hdu|opd|er[\/\w]*|عناية\s*مركزة|طوارئ)/i);
    if (wardMatch) {
      // Check if this row ONLY has the ward header (no patient data)
      const nonEmpty = cols.filter(c => c.trim()).length;
      const wardText = wardMatch[1].trim();
      if (nonEmpty <= 2) {
        // Extract ward number: "ward 20"/"جناح 20" -> "W20", "ICU"/"عناية مركزة" -> "ICU", "ER"/"طوارئ" -> "ER"
        const wNum = wardText.match(/(?:ward|جناح)\s*(\d+)/i);
        if (wNum) { currentWard = "W" + wNum[1]; }
        else if (wardText.includes("عناية") || /icu|nicu/i.test(wardText)) { currentWard = wardText.toUpperCase().includes("NICU") ? "NICU" : "ICU"; }
        else if (wardText.includes("طوارئ") || /^er/i.test(wardText)) { currentWard = "ER"; }
        else { currentWard = wardText.toUpperCase().split("/")[0]; }
        continue;
      }
    }

    // Try to extract patient from this row
    const name = (cols[colName] || "").trim();
    if (!name) continue;
    // Skip if it looks like a header or section label
    if (name.toLowerCase().includes("patient name") || name.toLowerCase().includes("list") || name.includes("اسم المريض") || name.includes("قائمة")) continue;

    const room = (cols[colRoom] || "").trim();
    const diagnosis = (cols[colDiagnosis] || "").trim();
    const doctor = (cols[colDoctor] || "").trim();
    const status = (cols[colStatus] || "").trim();

    // Determine severity code from status/category
    let code = 2; // default yellow
    const statusLower = status.toLowerCase();
    if (statusLower === "new" || statusLower === "critical" || statusLower === "red") code = 3;
    else if (statusLower === "chronic" || currentCategory === "Chronic") code = 1;

    // Build notes from status if it's descriptive
    let notes = "";
    if (status && !["new", "chronic", "active", ""].includes(statusLower)) {
      notes = status;
    }
    if (currentCategory === "Chronic") notes = notes ? "Chronic - " + notes : "Chronic";

    patients.push({
      name: name.slice(0, 200),
      civil: "",
      nat: "",
      ward: currentWard.slice(0, 30),
      room: room.slice(0, 30),
      code: Math.max(1, Math.min(3, code)),
      notes: notes.slice(0, 500),
      doctor: doctor.slice(0, 100),
      diagnosis: diagnosis.slice(0, 200),
      category: currentCategory,
    });
  }
  return patients;
}

// Simple CSV row parser (handles quoted fields with commas)
function parseCSVRow(line) {
  const result = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') { current += '"'; i++; }
      else if (ch === '"') { inQuotes = false; }
      else { current += ch; }
    } else {
      if (ch === '"') { inQuotes = true; }
      else if (ch === ',') { result.push(current); current = ""; }
      else { current += ch; }
    }
  }
  result.push(current);
  return result;
}

// Core sync logic — reusable by both manual sync and auto-sync
async function doSyncUnit(unit, uidForAudit) {
  const urlSnap = await db.ref("config/sheets/" + unit).once("value");
  const sheetUrl = urlSnap.val();
  if (!sheetUrl) return null; // no sheet configured

  const m = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9_-]+)/);
  if (!m) return null;
  const sheetId = m[1];
  const gidMatch = sheetUrl.match(/gid=(\d+)/);
  const gid = gidMatch ? gidMatch[1] : "0";
  const csvUrl = "https://docs.google.com/spreadsheets/d/" + sheetId + "/export?format=csv&gid=" + gid;

  // Fetch with retry for transient errors (429 rate limit, 5xx server errors)
  let res;
  for (let attempt = 0; attempt < 3; attempt++) {
    res = await fetch(csvUrl);
    if (res.ok) break;
    if ((res.status === 429 || res.status >= 500) && attempt < 2) {
      await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
      continue;
    }
    throw new Error("Failed to fetch sheet for " + unit + ": HTTP " + res.status);
  }
  const csv = await res.text();

  // Safety: detect HTML responses (login page, deleted sheet, error page)
  if (csv.trim().startsWith("<!") || csv.trim().startsWith("<html")) {
    throw new Error("Sheet returned HTML instead of CSV for " + unit + " — check sharing permissions");
  }

  const sheetPatients = parseSheetCSV(csv);

  // Safety: if sheet returns 0 patients but we had patients before, skip to prevent mass discharge
  const syncSnap0 = await db.ref("config/sheetSync/" + unit).once("value");
  const prevSync0 = syncSnap0.val() || {};
  if (sheetPatients.length === 0 && Object.keys(prevSync0).length > 0) {
    console.warn("Sheet returned 0 patients for " + unit + " but had " + Object.keys(prevSync0).length + " previously — skipping sync");
    return { added: 0, updated: 0, discharged: 0, unchanged: 0, total: 0, skipped: true, reason: "empty_sheet_safety" };
  }

  const dbSnap = await db.ref("patients/" + unit).once("value");
  const dbData = dbSnap.val() || {};
  // Filter out discharged patients from matching pool to prevent false matches and performance drag
  const dbEntries = Object.entries(dbData).filter(([, p]) => (p.category || "").toLowerCase() !== "discharged");

  const prevSync = prevSync0;

  let added = 0, discharged = 0, unchanged = 0;
  const newSyncState = {};
  const writes = {};

  // Deduplicate sheet patients: keep last occurrence per normalized key (most likely the updated version)
  // Use toLatin + stripVowels for cross-script dedup (Arabic "هاراكامان" == English "Harakaman")
  const seenSheet = new Map();
  for (let i = 0; i < sheetPatients.length; i++) {
    const sp = sheetPatients[i];
    if (!sp.name || !sp.name.trim()) continue;
    const latinName = stripVowels(toLatin(normName(sp.name)));
    const dedupKey = latinName + "|" + normWard(sp.ward) + "|" + normRoom(sp.room);
    seenSheet.set(dedupKey, i);
  }
  const dedupedPatients = [...seenSheet.values()].sort((a, b) => a - b).map(i => sheetPatients[i]);

  // Score-ranked matching: compute all match candidates, assign by highest score first
  // This prevents order-dependent mismatches where an earlier row steals a better match
  const candidates = [];
  for (let si = 0; si < dedupedPatients.length; si++) {
    const sp = dedupedPatients[si];
    if (!sp.name || !sp.name.trim()) continue;
    for (const [key, pat] of dbEntries) {
      const matchResult = findMatch(sp, [[key, pat]], prevSync);
      if (matchResult) {
        candidates.push({ si, sp, key, pat, score: matchResult.score });
      }
    }
  }
  candidates.sort((a, b) => b.score - a.score);

  const matchedDbKeys = new Set();
  const matchedSpIdxs = new Set();
  const spMatches = new Map(); // si -> { key, pat }

  for (const c of candidates) {
    if (matchedDbKeys.has(c.key) || matchedSpIdxs.has(c.si)) continue;
    matchedDbKeys.add(c.key);
    matchedSpIdxs.add(c.si);
    spMatches.set(c.si, { key: c.key, pat: c.pat });
  }

  // Process all sheet patients: matched ones are left untouched, unmatched get added
  for (let si = 0; si < dedupedPatients.length; si++) {
    const sp = dedupedPatients[si];
    if (!sp.name || !sp.name.trim()) continue;
    const match = spMatches.get(si);
    // Use DB key as sync state ID once matched (stable), fallback to composite key
    const spId = match ? match.key : (normName(sp.name) + "|" + normWard(sp.ward) + "|" + normRoom(sp.room));

    if (match) {
      // Existing patient — do NOT update their data (app edits take priority)
      newSyncState[spId] = match.key;
      unchanged++;
    } else {
      // New patient from sheet — add to database
      const newKey = db.ref("patients/" + unit).push().key;
      writes["patients/" + unit + "/" + newKey] = {
        name: sp.name.slice(0, 200), civil: (sp.civil || "").slice(0, 20),
        nat: (sp.nat || "").slice(0, 50), ward: (sp.ward || "").slice(0, 30),
        room: (sp.room || "").slice(0, 30), code: Math.max(1, Math.min(3, sp.code || 2)),
        notes: (sp.notes || "").slice(0, 500), doctor: (sp.doctor || "").slice(0, 100),
        diagnosis: (sp.diagnosis || "").slice(0, 200), category: sp.category || "Active",
        ts: Date.now(),
      };
      newSyncState[spId] = newKey; added++;
    }
  }

  // Discharge previously synced patients no longer in sheet
  const matchedKeySet = new Set(Object.values(newSyncState));
  for (const [, dbKey] of Object.entries(prevSync)) {
    if (!matchedKeySet.has(dbKey)) {
      const existing = dbData[dbKey];
      if (existing && (existing.category || "").toLowerCase() !== "discharged") {
        writes["patients/" + unit + "/" + dbKey] = { ...existing, category: "Discharged", ts: Date.now() };
        discharged++;
      }
    }
  }

  // Atomic multi-path write: faster, all-or-nothing, reduces Firebase billing
  if (Object.keys(writes).length > 0) {
    await db.ref().update(writes);
  }
  await db.ref("config/sheetSync/" + unit).set(newSyncState);

  if (added || discharged) {
    await db.ref("audit").push({
      action: "sheet_sync", unit, ts: Date.now(), uid: uidForAudit || "auto",
      detail: "+" + added + " -" + discharged + " =" + unchanged,
    });
  }

  return { added, updated: 0, discharged, unchanged, total: sheetPatients.length };
}

// Scheduled auto-sync: runs every 5 minutes, syncs all units with configured sheets
exports.autoSyncSheets = functions.region("europe-west1").pubsub
  .schedule("every 5 minutes")
  .timeZone("Asia/Kuwait")
  .onRun(async () => {
    const sheetsSnap = await db.ref("config/sheets").once("value");
    const sheets = sheetsSnap.val();
    if (!sheets) { console.log("No sheets configured"); return null; }

    const units = Object.keys(sheets).filter(u => /^[A-E]_(M|F)$/.test(u) && sheets[u]);
    let totalAdded = 0, totalDischarged = 0;

    for (const unit of units) {
      try {
        const result = await doSyncUnit(unit, "auto");
        if (result) {
          totalAdded += result.added;
          totalDischarged += result.discharged;
          if (result.added || result.discharged) {
            console.log("Auto-sync " + unit + ": +" + result.added + " -" + result.discharged);
          }
        }
      } catch (e) {
        console.error("Auto-sync failed for " + unit + ":", e.message);
        await db.ref("config/sheetErrors/" + unit).set({
          error: (e.message || "unknown").slice(0, 500),
          ts: Date.now(),
        }).catch(() => {});
      }
    }

    if (totalAdded || totalDischarged) {
      console.log("Auto-sync complete: +" + totalAdded + " -" + totalDischarged);
    }
    return null;
  });

// Scheduled daily backup: copies all patient data to backups/<date>
exports.dailyBackup = functions.region("europe-west1").pubsub
  .schedule("every 24 hours")
  .timeZone("Asia/Kuwait")
  .onRun(async () => {
    const snap = await db.ref("patients").once("value");
    const data = snap.val();
    if (!data) {
      console.log("No patient data to back up");
      return null;
    }
    const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    await db.ref("backups/" + date).set({
      ts: Date.now(),
      patients: data,
    });
    // Keep only last 30 days of backups
    const backupsSnap = await db.ref("backups").orderByKey().once("value");
    const keys = [];
    backupsSnap.forEach(child => { keys.push(child.key); });
    if (keys.length > 30) {
      const toDelete = keys.slice(0, keys.length - 30);
      const updates = {};
      toDelete.forEach(k => { updates[k] = null; });
      await db.ref("backups").update(updates);
    }
    console.log("Backup completed:", date, "patients:", Object.keys(data).length, "units");
    await db.ref("audit").push({
      action: "auto_backup",
      unit: "SYSTEM",
      ts: Date.now(),
      uid: "system",
    });
    return null;
  });
