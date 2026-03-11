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
