
// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

const app = express();

app.use(cors());                  // Allow cross-origin from your Flutter app
app.use(express.json({ limit: '1mb' })); // Parse JSON bodies

// ---- MySQL connection pool ----
let pool;
(async function initDb() {
  pool = await mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    connectionLimit: 8,
    timezone: 'Z',
    charset: 'utf8mb4_general_ci',
  });
  console.log('MySQL pool created');
})().catch((err) => {
  console.error('Failed to init DB pool:', err);
  process.exit(1);
});

// ---- Helpers ----
const isNonEmpty = (s) => typeof s === 'string' && s.length > 0;
const isEmailLike = (s) =>
  typeof s === 'string' && s.includes('@') && s.includes('.') && !/\s/.test(s);

function normalizePayload(body) {
  // Expect fields exactly like your Flutter client sends
  const username = (body.username || '').trim();
  const email = (body.email || '').trim();
  const password = body.password || '';

  const phone_country_code = (body.phone_country_code || '').trim(); // '44'
  const phone_number = (body.phone_number || '').trim();             // '7123456789'
  const phone_e164 = (body.phone_e164 || '').trim();                 // '+447123456789' or empty

  // Security Q&A (three pairs)
  const secuQuestion1 = (body.secuQuestion1 || '').trim();
  const secuAns1 = (body.secuAns1 || '').trim();
  const secuQuestion2 = (body.secuQuestion2 || '').trim();
  const secuAns2 = (body.secuAns2 || '').trim();
  const secuQuestion3 = (body.secuQuestion3 || '').trim();
  const secuAns3 = (body.secuAns3 || '').trim();

  return {
    username,
    email,
    password,
    phone_country_code,
    phone_number,
    phone_e164,
    secu: [
      { q: secuQuestion1, a: secuAns1 },
      { q: secuQuestion2, a: secuAns2 },
      { q: secuQuestion3, a: secuAns3 },
    ],
  };
}

function validatePayload(p) {
  const errors = [];

  // At least one identifier: username or email. (Adjust if you allow phone-only signups)
  if (!isNonEmpty(p.username) && !isNonEmpty(p.email)) {
    errors.push('Either username or email is required.');
  }
  if (isNonEmpty(p.email) && !isEmailLike(p.email)) {
    errors.push('Email format looks invalid.');
  }

  // Password: enforce basic rules; you already validate in Flutter
  if (!isNonEmpty(p.password) || p.password.length < 8) {
    errors.push('Password must be at least 8 characters.');
  }

  // If phone fields are provided, do a minimal sanity check
  if (isNonEmpty(p.phone_country_code) || isNonEmpty(p.phone_number) || isNonEmpty(p.phone_e164)) {
    if (!/^\d{1,8}$/.test(p.phone_country_code)) {
      errors.push('phone_country_code must be digits only, up to 8 chars.');
    }
    if (!/^\d{3,20}$/.test(p.phone_number)) {
      errors.push('phone_number must be digits only, 3–20 chars.');
    }
    if (isNonEmpty(p.phone_e164) && !/^\+\d{6,20}$/.test(p.phone_e164)) {
      errors.push('phone_e164 must be in +<digits> format.');
    }
  }

  // Security questions: all three required with non-empty answers
  p.secu.forEach((item, idx) => {
    if (!isNonEmpty(item.q)) errors.push(`Security question ${idx + 1} is required.`);
    if (!isNonEmpty(item.a)) errors.push(`Security answer ${idx + 1} is required.`);
    if (item.a.length < 3) errors.push(`Security answer ${idx + 1} must be at least 3 chars.`);
    if (item.a.length > 255) errors.push(`Security answer ${idx + 1} must be ≤ 255 chars.`);
  });

  // Ensure questions are unique (optional, mimics your client)
  const uniqQs = new Set(p.secu.map((x) => x.q));
  if (uniqQs.size !== p.secu.length) {
    errors.push('Security questions must all be different.');
  }

  return errors;
}

// ---- Signup endpoint ----
app.post('/api/signup', async (req, res) => {
  try {
    const payload = normalizePayload(req.body);
    const errs = validatePayload(payload);
    if (errs.length) {
      return res.status(400).json({ error: errs.join(' ') });
    }

    const saltRounds = Number(process.env.BCRYPT_ROUNDS || 12);
    const password_hash = await bcrypt.hash(payload.password, saltRounds);

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Check duplicates (username, email)
      if (isNonEmpty(payload.username)) {
        const [rowsU] = await conn.execute(
          'SELECT id FROM users WHERE username = ? LIMIT 1',
          [payload.username]
        );
        if (Array.isArray(rowsU) && rowsU.length) {
          await conn.rollback();
          conn.release();
          return res.status(409).json({ error: 'Username already exists.' });
        }
      }
      if (isNonEmpty(payload.email)) {
        const [rowsE] = await conn.execute(
          'SELECT id FROM users WHERE email = ? LIMIT 1',
          [payload.email]
        );
        if (Array.isArray(rowsE) && rowsE.length) {
          await conn.rollback();
          conn.release();
          return res.status(409).json({ error: 'Email already exists.' });
        }
      }

      // Insert user
      const [result] = await conn.execute(
        `INSERT INTO users
         (username, email, password_hash, phone_country_code, phone_number, phone_e164)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          payload.username || '',              // store empty string if not provided
          payload.email || '',
          password_hash,
          payload.phone_country_code || null,  // store NULL if not provided
          payload.phone_number || null,
          payload.phone_e164 || null,
        ]
      );

      const userId = result.insertId;

      // Insert security Q&A (3 rows)
      for (const qa of payload.secu) {
        await conn.execute(
          `INSERT INTO user_security_questions (user_id, question, answer)
           VALUES (?, ?, ?)`,
          [userId, qa.q, qa.a]
        );
      }

      await conn.commit();
      conn.release();

      return res.status(201).json({ id: userId, message: 'User created' });
    } catch (err) {
      await pool.query('ROLLBACK'); // safe rollback if txn was open
      if (conn) conn.release();
      console.error('Signup transaction error:', err);
      return res.status(500).json({ error: 'Server error during signup.' });
    }
  } catch (e) {
    console.error('Unexpected signup error:', e);
    return res.status(500).json({ error: 'Unexpected server error.' });
  }
});

// Health check (optional)
app.get('/health', (_req, res) => res.json({ ok: true }));

// Start
const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`API listening on port ${port}`);
});
``
