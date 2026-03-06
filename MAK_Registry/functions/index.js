const { onCall, HttpsError } = require("firebase-functions/v2/https");
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

exports.verifyPin = onCall({ region: "europe-west1", cors: true }, async (request) => {
  // Require authentication
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Must be authenticated");
  }

  const { unit, pin } = request.data;
  const validUnits = /^(A_M|A_F|B_M|B_F|C_M|C_F|D_M|D_F|E_M|E_F|ADMIN)$/;
  if (!unit || !validUnits.test(unit)) {
    throw new HttpsError("invalid-argument", "Invalid unit");
  }
  if (!pin || typeof pin !== "string" || pin.length < 4 || pin.length > 6) {
    throw new HttpsError("invalid-argument", "Invalid PIN");
  }

  // Rate limit by IP
  const ip = request.rawRequest?.ip || request.auth.uid || "unknown";
  if (!checkRateLimit(ip)) {
    throw new HttpsError("resource-exhausted", "Too many attempts. Try again later.");
  }

  // Read stored PIN from database
  const snap = await db.ref("pins/" + unit).once("value");
  const stored = snap.val();
  if (!stored) {
    throw new HttpsError("not-found", "PIN not configured for this unit");
  }

  const match = verifyPin(pin, stored);
  if (!match) {
    recordFail(ip);
    // Audit log
    await db.ref("audit").push({
      action: "login_fail",
      unit,
      ts: Date.now(),
      uid: request.auth.uid || "anon",
    });
    throw new HttpsError("permission-denied", "Wrong PIN");
  }

  resetFails(ip);
  // Audit log
  await db.ref("audit").push({
    action: "login",
    unit,
    ts: Date.now(),
    uid: request.auth.uid || "anon",
  });

  return { success: true, unit };
});

// Set/update a PIN (admin only — must verify ADMIN PIN first)
exports.setPin = onCall({ region: "europe-west1", cors: true }, async (request) => {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Must be authenticated");
  }

  const { adminPin, unit, newPin } = request.data;
  const validUnits = /^(A_M|A_F|B_M|B_F|C_M|C_F|D_M|D_F|E_M|E_F|ADMIN)$/;
  if (!unit || !validUnits.test(unit)) {
    throw new HttpsError("invalid-argument", "Invalid unit");
  }
  if (!newPin || typeof newPin !== "string" || newPin.length < 4 || newPin.length > 6) {
    throw new HttpsError("invalid-argument", "PIN must be 4-6 digits");
  }
  if (!adminPin || typeof adminPin !== "string") {
    throw new HttpsError("invalid-argument", "Admin PIN required");
  }

  // Verify admin PIN
  const adminSnap = await db.ref("pins/ADMIN").once("value");
  const adminStored = adminSnap.val();
  if (!adminStored || !verifyPin(adminPin, adminStored)) {
    throw new HttpsError("permission-denied", "Invalid admin PIN");
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
    uid: request.auth.uid || "anon",
  });

  return { success: true };
});

// Check if a unit has a PIN configured (doesn't reveal the PIN)
exports.hasPins = onCall({ region: "europe-west1", cors: true }, async (request) => {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Must be authenticated");
  }

  const snap = await db.ref("pins").once("value");
  const pins = snap.val() || {};
  const result = {};
  for (const key of Object.keys(pins)) {
    result[key] = true;
  }
  return result;
});
