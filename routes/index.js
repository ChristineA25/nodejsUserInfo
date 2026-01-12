
// routes/index.js
const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

console.log('✅ routes/index.js loaded');

// --- MySQL pool (Railway env vars) ---
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: Number(process.env.MYSQL_PORT || 3306),
  connectionLimit: 10,
  charset: 'utf8mb4',
});

// --- Helpers ---
function trimStr(v) {
  return (v ?? '').toString().trim();
}
function onlyOneIdentifier(body) {
  const ids = [trimStr(body.username), trimStr(body.email), trimStr(body.phone_number)]
    .filter(v => v !== '');
  return ids.length === 1;
}
function isStrongPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8;
}

// --- Routes ---

// Home
router.get('/', (_req, res) => {
  res.send('Hello from Railway!');
});

// Health
router.get('/health', async (_req, res) => {
  try {
    const conn = await pool.getConnection();
    await conn.ping();
    conn.release();
    res.json({ status: 'ok', ts: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ status: 'db-error', detail: String(err?.message || err) });
  }
});

/**
 * POST /api/signup
 * Expected JSON body (exactly one identifier):
 *  - username OR email OR (phone_country_code + phone_number [+ phone_e164])
 *  - password
 *  - secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3
 *
 * Returns:
 *  - 201 { ok: true, userId, reqId }
 *  - 400/409/500 with { error, reqId, detail? }
 */
router.post('/api/signup', async (req, res) => {
  const reqId = req.get('X-Client-Request-Id') || crypto.randomUUID();

  try {
    // Parse & sanitize
    const body = req.body || {};
    const username = trimStr(body.username);
    const email = trimStr(body.email);
    const password = body.password;
    const phoneCountryCode = trimStr(body.phone_country_code);
    const phoneNumber = trimStr(body.phone_number);
    const phoneE164 = trimStr(body.phone_e164);

    const q1 = trimStr(body.secuQuestion1);
    const a1 = trimStr(body.secuAns1);
    const q2 = trimStr(body.secuQuestion2);
    const a2 = trimStr(body.secuAns2);
    const q3 = trimStr(body.secuQuestion3);
    const a3 = trimStr(body.secuAns3);

    // Validation
    if (!onlyOneIdentifier(body)) {
      return res.status(400).json({ error: 'Provide exactly one of username, email, or phone_number.', reqId });
    }
    if (!isStrongPassword(password)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.', reqId });
    }
    if (!q1 || !q2 || !q3 || !a1 || !a2 || !a3) {
      return res.status(400).json({ error: 'All three security questions and answers are required.', reqId });
    }
    if (new Set([q1, q2, q3]).size !== 3) {
      return res.status(400).json({ error: 'Each security question must be different.', reqId });
    }
    if (phoneNumber && !phoneCountryCode) {
      return res.status(400).json({ error: 'phone_country_code is required when phone_number is provided.', reqId });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(String(password), 12);

    // Insert
    const conn = await pool.getConnection();
    try {
      // Optional uniqueness checks (remove if you rely on DB UNIQUE constraints)
      if (username) {
        const [r] = await conn.execute('SELECT id FROM users WHERE username = ?', [username]);
        if (r.length) return res.status(409).json({ error: 'Username already exists.', reqId });
      }
      if (email) {
        const [r] = await conn.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (r.length) return res.status(409).json({ error: 'Email already exists.', reqId });
      }
      if (phoneNumber) {
        const [r] = await conn.execute(
          'SELECT id FROM users WHERE phone_country_code = ? AND phone_number = ?',
          [phoneCountryCode, phoneNumber]
        );
        if (r.length) return res.status(409).json({ error: 'Phone number already exists.', reqId });
      }

      const [result] = await conn.execute(
        `INSERT INTO users
         (username, email, password_hash,
          phone_country_code, phone_number, phone_e164,
          secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          username || null,
          email || null,
          passwordHash,
          phoneCountryCode || null,
          phoneNumber || null,
          phoneE164 || null,
          q1, a1, q2, a2, q3, a3,
        ]
      );

      return res.status(201).json({ ok: true, userId: result.insertId, reqId });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error('Signup error:', err);
    const detail = String(err?.message || err);
    return res.status(500).json({ error: 'Internal error', detail, reqId });
  }
});

module.exports = router;
