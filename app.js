
// app.js
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { pool } = require('./db');

const app = express();
app.use(express.json());

// AES encryption settings
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'df693b8a07dda28fd08824a9fd9fbf1b2cfbc37568d1fa6ab613038beddf24e4'; // 32 chars
const IV_LENGTH = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Health check
app.get('/health', (req, res) => {
  ts: new Date().toISOString() });
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
      secuAns3
    } = req.body || {};

    if (!password) return res.status(400).json({ error: 'password_required' });

    // Hash password
    const hashedPassword = await bcrypt.hash(String(password), 12);

    // Add timestamp and encrypt all info
    const signupData = JSON.stringify({
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
      timestamp: new Date().toISOString()
    });
    const encryptedUserID = encrypt(signupData);

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
      phone_country_code ?? null,
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
    return res.status(500).json({ error: err.message || 'unknown_error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
});
``
