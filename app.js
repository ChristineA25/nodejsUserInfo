
// Only load .env during local development
if (process.env.NODE_ENV !== 'production') {
  try { require('dotenv').config(); } catch (_) {}
}

// app.js
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');            // password hashing
const crypto = require('crypto');              // AES-256-GCM for encryption
const { pool } = require('./db');              // db.js must export a mysql2/promise pool

const app = express();

// Parse JSON (needed for req.body)
app.use(express.json());

/**
 * Encrypts plain text using AES-256-GCM.
 * Requires process.env.ENCRYPTION_KEY to be a base64 string that decodes to 32 bytes.
 * Uses a random 12-byte IV for each encryption.
 * Returns a base64-packed string: "iv:ciphertext:tag".
 */
function encryptToBase64(plainText) {
  if (plainText === null || plainText === undefined) return null;

  const keyB64 = process.env.ENCRYPTION_KEY;
  if (!keyB64) {
    throw new Error('ENCRYPTION_KEY_missing');
  }

  const key = Buffer.from(keyB64, 'base64');
  if (key.length !== 32) {
    throw new Error('ENCRYPTION_KEY_must_be_32_bytes_base64');
  }

  // 12-byte IV is recommended for GCM
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(String(plainText), 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return [
    iv.toString('base64'),
    ciphertext.toString('base64'),
    authTag.toString('base64'),
  ].join(':');
}

// Simple health endpoint for Railway
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

// --- API routes ---

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

    // Hash the password (bcryptjs)
    const hashed = await bcrypt.hash(String(password), 12);

    // Prepare encrypted fields
    // - email_enc: encrypt "email" as provided (nullable)
    // - phone_number_enc: encrypt ONLY phone_number (exclude country code)
    let emailEnc = null;
    let phoneEnc = null;

    try {
      emailEnc = email ? encryptToBase64(email) : null;

      // Optionally normalize to digits only. If you prefer raw as-entered (still no country code), use `phone_number` directly.
      const rawPhone = phone_number ?? null; // no country code by design
      // const normalizedPhone = rawPhone ? String(rawPhone).replace(/\D+/g, '') : null;
      // phoneEnc = normalizedPhone ? encryptToBase64(normalizedPhone) : null;
      phoneEnc = rawPhone ? encryptToBase64(String(rawPhone)) : null;
    } catch (encErr) {
      // If encryption fails, do not insert partial data
      return res.status(500).json({ error: encErr.message || 'encryption_failed' });
    }

    // IMPORTANT: Plain columns `email` and `phone_number` have been DROPPED.
    // Insert only the encrypted fields plus your remaining metadata columns.
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
      hashed,
      phone_country_code ?? null,
      secuQuestion1 ?? null,
      secuAns1 ?? null,
      secuQuestion2 ?? null,
      secuAns2 ?? null,
      secuQuestion3 ?? null,
      secuAns3 ?? null,
      emailEnc,            // encrypted email
      phoneEnc,            // encrypted phone (local part only)
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

// 404 catch-all (after routes and static)
app.use((req, res) => {
  const fallback404 = path.join(__dirname, 'views', '404.html');
  res.status(404).sendFile(fallback404, (sendErr) => {
    if (sendErr) {
      res.status(404).type('text').send('404 – Not Found');
    }
  });
});

// Single listener — Railway sets PORT for you
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
  if (!indexRouterMounted) {
    console.warn('⚠️ indexRouter was not mounted. Only static files and /health + /api/signup are active.');
  }
});
