
// app.js
// --------------------------------------------------------------------------------------
// Production-ready Express app with deterministic AES‑SIV encryption for email & phone.
// - email_enc, phone_number_enc: AES‑SIV (deterministic, same input -> same ciphertext)
// - password: bcrypt hash with random salt (NON-deterministic, as it should be)
// Requirements:
//   npm i express bcryptjs @stablelib/aes-siv path
//   process.env.ENCRYPTION_SIV_KEY = base64(64 bytes)
//   db.js must export { pool } from mysql2/promise
// --------------------------------------------------------------------------------------

// Only load .env during local development
if (process.env.NODE_ENV !== 'production') {
  try { require('dotenv').config(); } catch (_) {}
}

const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');         // password hashing (salted, non-deterministic)
const { AES_SIV } = require('@stablelib/aes-siv');
const { pool } = require('./db');           // db.js must export a mysql2/promise pool

const app = express();

// Parse JSON (needed for req.body)
app.use(express.json());

// --------------------------------------------------------------------------------------
// AES‑SIV deterministic helpers
// --------------------------------------------------------------------------------------
function getSivKey() {
  const keyB64 = process.env.ENCRYPTION_SIV_KEY;
  if (!keyB64) throw new Error('ENCRYPTION_SIV_KEY_missing');
  const key = Buffer.from(keyB64, 'base64');
  if (key.length !== 64) {
    // AES‑SIV uses two 256‑bit subkeys internally → 64‑byte master key recommended
    throw new Error('ENCRYPTION_SIV_KEY_must_be_64_bytes_base64');
  }
  return new Uint8Array(key);
}

/**
 * Deterministic AEAD encryption with AES‑SIV:
 * - Same plaintext (+ same AAD) -> same ciphertext for a given key.
 * - No random IV/nonce is required or used.
 * - Returns base64 ciphertext.
 * - `associatedData` is an optional array of strings/Uint8Arrays for domain separation.
 */
function encryptDeterministicToBase64(plainText, associatedData = []) {
  if (plainText === null || plainText === undefined) return null;
  const key = getSivKey();
  const siv = new AES_SIV(key);

  const pt = Buffer.from(String(plainText), 'utf8');
  const aad = (associatedData || []).map((s) =>
    s instanceof Uint8Array ? s : Buffer.from(String(s), 'utf8')
  );

  const ct = siv.seal(pt, aad); // Uint8Array
  return Buffer.from(ct).toString('base64');
}

/**
 * AES‑SIV decryption helper (optional for admin tools).
 */
function decryptDeterministicFromBase64(b64, associatedData = []) {
  if (b64 === null || b64 === undefined) return null;
  const key = getSivKey();
  const siv = new AES_SIV(key);

  const ct = Buffer.from(String(b64), 'base64');
  const aad = (associatedData || []).map((s) =>
    s instanceof Uint8Array ? s : Buffer.from(String(s), 'utf8')
  );

  const pt = siv.open(new Uint8Array(ct), aad);
  if (!pt) throw new Error('siv_decryption_failed');
  return Buffer.from(pt).toString('utf8');
}

// --------------------------------------------------------------------------------------
// Health + Static + Optional index router
// --------------------------------------------------------------------------------------
app.get('/health', (req, res) => {
  res.status(200).send('ok');
});

// Serve static files from "public"
app.use(express.static(path.join(__dirname, 'public')));

// Try to attach the index router (optional)
let indexRouterMounted = false;
try {
  const indexRouter = require('./routes/index');
  app.use('/', indexRouter);
  indexRouterMounted = true;
  console.log('✅ indexRouter mounted');
} catch (err) {
  console.error('❌ Failed to load ./routes/index:', err);
}

// --------------------------------------------------------------------------------------
// API routes
// --------------------------------------------------------------------------------------

/**
 * POST /api/signup
 * Expects JSON body including a client-supplied userID (from Flutter).
 * Example body:
 * {
 *   "userID": "123456789012",
 *   "identifierType": "username" | "email" | "phone",
 *   "username": "railway_test",          // when identifierType === "username"
 *   "email": "railway@example.com",      // when identifierType === "email"
 *   "phone_country_code": "+44",         // when identifierType === "phone"
 *   "phone_number": "07123456789",       // local part only (no +CC)
 *   "phoneE164": "+447123456789",        // optional normalized (not stored unless you add a column)
 *   "password": "Passw0rd!123",
 *   "secuQuestion1": "First pet?",
 *   "secuAns1": "Milo",
 *   "secuQuestion2": "Birth city?",
 *   "secuAns2": "Hong Kong",
 *   "secuQuestion3": "Favourite colour?",
 *   "secuAns3": "Blue"
 * }
 */
app.post('/api/signup', async (req, res) => {
  try {
    const {
      userID,
      identifierType,
      username, password, email,
      phone_country_code, phone_number, phoneE164,
      secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3
    } = req.body || {};

    // Basic validation — adjust as needed
    if (userID === undefined || userID === null || userID === '') {
      return res.status(400).json({ error: 'userID_required' });
    }
    if (!password) {
      return res.status(400).json({ error: 'password_required' });
    }

    // Optional: enforce identifierType coherence
    if (identifierType === 'username' && !username) {
      return res.status(400).json({ error: 'username_required' });
    }
    if (identifierType === 'email' && !email) {
      return res.status(400).json({ error: 'email_required' });
    }
    if (identifierType === 'phone' && !phone_number) {
      return res.status(400).json({ error: 'phone_number_required' });
    }

    // Hash the password (bcryptjs) — RANDOMIZED (kept intentionally non-deterministic)
    const hashed = await bcrypt.hash(String(password), 12);

    // Prepare deterministic encrypted fields (AES‑SIV)
    // - email_enc: deterministic encryption of (trimmed) email
    // - phone_number_enc: deterministic encryption of ONLY the local number (as per your schema)
    let emailEnc = null;
    let phoneEnc = null;

    try {
      // Normalize email minimally (trim); if you want case-insensitive equality,
      // you can lower-case here, but you will be storing the lowercased value (encrypted).
      const emailForEnc = email ? String(email).trim() : null;
      emailEnc = emailForEnc
        ? encryptDeterministicToBase64(emailForEnc, ['loginTable', 'email'])
        : null;

      // Keep your original policy: store ONLY local phone (no country code) in *_enc
      const localPhone = phone_number ?? null;
      const phoneForEnc = localPhone ? String(localPhone) : null;
      phoneEnc = phoneForEnc
        ? encryptDeterministicToBase64(phoneForEnc, ['loginTable', 'phone'])
        : null;

    } catch (encErr) {
      // If encryption fails, do not insert partial data
      return res.status(500).json({ error: encErr.message || 'encryption_failed' });
    }

    // Insert only encrypted fields + remaining metadata columns
    const sql = `
      INSERT INTO loginTable
        (userID, username, password, phone_country_code,
         secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3,
         email_enc, phone_number_enc)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const params = [
      userID,
      username ?? null,
      hashed,                              // bcrypt hash (non-deterministic by design)
      phone_country_code ?? null,
      secuQuestion1 ?? null,
      secuAns1 ?? null,
      secuQuestion2 ?? null,
      secuAns2 ?? null,
      secuQuestion3 ?? null,
      secuAns3 ?? null,
      emailEnc,                            // AES‑SIV deterministic ciphertext (base64)
      phoneEnc,                            // AES‑SIV deterministic ciphertext (base64)
    ];

    const [result] = await pool.execute(sql, params);

    // Return the userID provided by client
    return res.status(201).json({ userID });
  } catch (err) {
    const msg = (err && err.message) ? err.message : 'unknown_error';
    const code = (err && err.code) ? err.code : null;

    // Example: ER_DUP_ENTRY for unique constraint violation
    if (code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'duplicate_identifier' });
    }

    return res.status(500).json({ error: msg });
  }
});

// --------------------------------------------------------------------------------------
// 404 catch-all (after routes and static)
// --------------------------------------------------------------------------------------
app.use((req, res) => {
  const fallback404 = path.join(__dirname, 'views', '404.html');
  res.status(404).sendFile(fallback404, (sendErr) => {
    if (sendErr) {
      res.status(404).type('text').send('404 – Not Found');
    }
  });
});

// --------------------------------------------------------------------------------------
// Single listener — Railway sets PORT for you
// --------------------------------------------------------------------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
  if (!indexRouterMounted) {
    console.warn('⚠️ indexRouter was not mounted. Only static files and /health + /api/signup are active.');
  }
});
