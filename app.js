
// app.js
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { pool } = require('./db');

const app = express();
app.use(express.json());

// AES encryption settings
// Use a 32-byte key for AES-256. If you store it as 64 hex chars in ENV, read with 'hex'.
const ENCRYPTION_KEY =
  process.env.ENCRYPTION_KEY ||
  'df693b8a07dda28fd08824a9fd9fbf1b2cfbc37568d1fa6ab613038beddf24e4'; // 64 hex chars = 32 bytes
const IV_LENGTH = 16; // bytes

function encrypt(plainText) {
  // iv must be 16 bytes for aes-256-cbc
  const iv = crypto.randomBytes(IV_LENGTH);
  // IMPORTANT: tell Buffer the key is hex-encoded
  const key = Buffer.from(ENCRYPTION_KEY, 'hex');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  // Return iv + ciphertext in hex for storage
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', ts: new Date().toISOString() });
});

// Sign-up route
app.post('/api/signup', async (req, res) => {
  try {
    const {
      username,
      password,
      email,
      phone_country_code,
      phone_number,
      secuQuestion1,
      secuAns1,
      secuQuestion2,
      secuAns2,
      secuQuestion3,
      secuAns3,
      // Optional: if the client sends its own click time (clientTimestamp),
      // we will include it in the encrypted record too.
      clientTimestamp
    } = req.body || {};

    if (!password) {
      return res.status(400).json({ error: 'password_required' });
    }

    // Hash password (bcrypt)
    const hashedPassword = await bcrypt.hash(String(password), 12);

    // Build payload to encrypt as userID (include server timestamp AND optional client timestamp)
    const payloadToEncrypt = {
      username,
      email,
      phone_country_code,
      phone_number,
      secuQuestion1,
      secuAns1,
      secuQuestion2,
      secuAns2,
      secuQuestion3,
      secuAns3,
      serverTimestamp: new Date().toISOString(),
      ...(clientTimestamp ? { clientTimestamp } : {})
    };

    const encryptedUserID = encrypt(JSON.stringify(payloadToEncrypt));

    // Insert into MySQL
    const sql = `
      INSERT INTO loginTable
      (userID, username, password, email, phone_country_code, phone_number,
       secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
      encryptedUserID,
      username ?? null,
      hashedPassword,
      email ?? null,
      // Store country code without '+' if your DB shows it that way, else keep as-is:
      // (Your screenshots show values like "44". If you want "+44", remove the replace.)
      (phone_country_code ?? null)?.toString().replace(/^\+/, '') || null,
      phone_number ?? null,
      secuQuestion1 ?? null,
      secuAns1 ?? null,
      secuQuestion2 ?? null,
      secuAns2 ?? null,
      secuQuestion3 ?? null,
      secuAns3 ?? null
    ];

    await pool.execute(sql, params);
    return res.status(201).json({ userID: encryptedUserID });
  } catch (err) {
    console.error(err);
    const msg = err && err.message ? err.message : 'unknown_error';
    return res.status(500).json({ error: msg });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
});
