
// Only load .env during local development
if (process.env.NODE_ENV !== 'production') {
  try { require('dotenv').config(); } catch (_) {}
}

// app.js
'use strict';

const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { pool } = require('./db'); // mysql2/promise pool

const app = express();
app.use(express.json());

/* ------------------------------------------------------------------ */
/*                          Key Management                             */
/* ------------------------------------------------------------------ */
/**
 * We use one base64 key for deterministic tokens (HMAC) and one for bcrypt salt cost.
 * - DETERMINISTIC_KEY: 32 bytes base64 (used for HMAC-SHA256 -> base64 output)
 *   Same input + same key => same token (deterministic), suitable for UNIQUE index.
 */
function loadKeyFromEnv(envName, expectedLen) {
  const b64 = process.env[envName];
  if (!b64) throw new Error(`${envName}_missing`);
  const buf = Buffer.from(b64, 'base64');
  if (buf.length !== expectedLen) {
    throw new Error(`${envName}_must_be_${expectedLen}_bytes_base64`);
  }
  return buf;
}

let DET_KEY; // for deterministic tokens (HMAC)
try {
  DET_KEY = loadKeyFromEnv('DETERMINISTIC_KEY', 32);
} catch (e) {
  console.warn('⚠️ Key load warning:', e.message);
}

/* ------------------------------------------------------------------ */
/*                        Deterministic “Encryption”                   */
/* ------------------------------------------------------------------ */
/**
 * Returns a deterministic, keyed token (base64 of 32-byte HMAC-SHA256).
 * This is not reversible cryptography (not ciphertext), but:
 *  - It's deterministic for equality checks and UNIQUE constraints.
 *  - It hides the plaintext without the key.
 */
function detTokenBase64(plain) {
  if (plain === null || plain === undefined) return null;
  if (!DET_KEY) throw new Error('DETERMINISTIC_KEY_missing');
  const mac = crypto.createHmac('sha256', DET_KEY)
    .update(String(plain), 'utf8')
    .digest(); // 32 bytes
  return mac.toString('base64'); // 44 chars
}

/* ------------------------------------------------------------------ */
/*                        Normalization Helpers                        */
/* ------------------------------------------------------------------ */
function normalizeEmail(email) {
  if (!email) return null;
  return String(email).trim().toLowerCase();
}

/**
 * Build/validate E.164: "+<digits>", typically 6..15 digits after '+'.
 * Prefer `phoneE164` from client if valid; else combine CC + local.
 */
function buildE164({ phoneE164, phone_country_code, phone_number }) {
  const isValidE164 = (v) => typeof v === 'string' && /^\+\d{6,15}$/.test(v);

  if (isValidE164(phoneE164)) return phoneE164;

  const ccRaw = (phone_country_code || '').toString().trim();
  const localRaw = (phone_number || '').toString().trim();

  if (!ccRaw.startsWith('+')) throw new Error('invalid_country_code');
  const ccDigits = ccRaw.replace(/[^\d]/g, '');   // keep digits only
  const localDigits = localRaw.replace(/\D+/g, ''); // keep digits only

  const combined = `+${ccDigits}${localDigits}`;
  if (!isValidE164(combined)) throw new Error('invalid_e164_combination');
  return combined;
}

/* ------------------------------------------------------------------ */
/*                         Health & Static                             */
/* ------------------------------------------------------------------ */
app.get('/health', (req, res) => res.status(200).send('ok'));
app.use(express.static(path.join(__dirname, 'public')));

let indexRouterMounted = false;
try {
  const indexRouter = require('./routes/index');
  app.use('/', indexRouter);
  indexRouterMounted = true;
  console.log('✅ indexRouter mounted');
} catch (err) {
  console.error('❌ Failed to load ./routes/index:', err.message);
}

/* ------------------------------------------------------------------ */
/*                             API: Signup                             */
/* ------------------------------------------------------------------ */
/**
 * POST /api/signup
 * Body (from Flutter):
 * {
 *   "userID": "123456789012",
 *   "identifierType": "username" | "email" | "phone",
 *   "username": "...",                 // when identifierType === "username"
 *   "email": "...",                    // when identifierType === "email"
 *   "phone_country_code": "+44",       // when identifierType === "phone"
 *   "phone_number": "7123456789",      // local (no +CC)
 *   "phoneE164": "+447123456789",      // optional; preferred if valid
 *   "password": "Passw0rd!123",
 *   "secuQuestion1": "...", "secuAns1": "...",
 *   "secuQuestion2": "...", "secuAns2": "...",
 *   "secuQuestion3": "...", "secuAns3": "..."
 * }
 *
 * Behavior:
 * - email_enc        = deterministic token of normalized email        (base64 HMAC)
 * - phone_number_enc = deterministic token of E.164 phone            (base64 HMAC)
 * - password         = bcrypt hash (non-deterministic, secure)
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

    // Basic validation
    if (!userID)    return res.status(400).json({ error: 'userID_required' });
    if (!password)  return res.status(400).json({ error: 'password_required' });

    if (identifierType === 'username' && !username) {
      return res.status(400).json({ error: 'username_required' });
    }
    if (identifierType === 'email' && !email) {
      return res.status(400).json({ error: 'email_required' });
    }
    if (identifierType === 'phone' && !phone_number && !phoneE164) {
      return res.status(400).json({ error: 'phone_number_required' });
    }

    // 1) Hash the password (best practice; do NOT make deterministic)
    const passwordHash = await bcrypt.hash(String(password), 12);

    // 2) Compute deterministic tokens for email and phone
    let emailEnc = null;            // deterministic token for normalized email
    let phoneEnc = null;            // deterministic token for E.164 phone
    let phoneE164Final = null;      // the canonical E.164 we tokenized

    try {
      if (email) {
        const normEmail = normalizeEmail(email);
        emailEnc = normEmail ? detTokenBase64(normEmail) : null;
      }

      if (identifierType === 'phone' || phoneE164) {
        phoneE164Final = buildE164({
          phoneE164,
          phone_country_code,
          phone_number
        });
        phoneEnc = detTokenBase64(phoneE164Final);
      }
    } catch (tokErr) {
      return res.status(500).json({ error: tokErr.message || 'tokenization_failed' });
    }

    // 3) Insert into DB (your schema from the screenshot)
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
      passwordHash,
      phone_country_code ?? null,
      secuQuestion1 ?? null,
      secuAns1 ?? null,
      secuQuestion2 ?? null,
      secuAns2 ?? null,
      secuQuestion3 ?? null,
      secuAns3 ?? null,
      emailEnc,       // deterministic token for email
      phoneEnc        // deterministic token for E.164 phone
    ];

    const [result] = await pool.execute(sql, params);
    return res.status(201).json({ userID });
  } catch (err) {
    const msg  = (err && err.message) ? err.message : 'unknown_error';
    const code = (err && err.code)    ? err.code    : null;

    if (code === 'ER_DUP_ENTRY') {
      // Your schema shows UNIQUE on email_enc and phone_number_enc
      return res.status(409).json({ error: 'duplicate_identifier' });
    }
    return res.status(500).json({ error: msg });
  }
});

/* ------------------------------------------------------------------ */
/*                        404 & Server Listen                          */
/* ------------------------------------------------------------------ */
app.use((req, res) => {
  const fallback404 = path.join(__dirname, 'views', '404.html');
  res.status(404).sendFile(fallback404, (sendErr) => {
    if (sendErr) res.status(404).type('text').send('404 – Not Found');
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
  if (!indexRouterMounted) {
    console.warn('⚠️ indexRouter was not mounted. Only static files and /health + /api/signup are active.');
  }
});
