
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
  const iv = crypto.randomBytes(IV_LENGTH);        // iv must be 16 bytes for aes-256-cbc
  const key = Buffer.from(ENCRYPTION_KEY, 'hex');  // tell Buffer the key is hex-encoded
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  // Return iv + ciphertext in hex for storage or transport
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Helpers
const asTrimmedOrNull = (v) =>
  v === undefined || v === null ? null : String(v).trim();

const normalizeCountryCode = (v) => {
  const s = asTrimmedOrNull(v);
  if (s === null) return null;
  // Store without '+' to match your screenshots ("44"). Remove this replace() if you prefer "+44".
  return s.replace(/^\+/, '');
};

app.get('/', (req, res) => {
  res.send('Welcome to the Save to Plant API. Use /health or /api/signup.');
});

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
      clientTimestamp,

      // NEW: allow client to send a program/user-generated identifier
      // We check both 'useID' and 'userID' to be flexible with client payloads.
      useID,
      userID: clientUserID
    } = req.body || {};

    if (!password) {
      return res.status(400).json({ error: 'password_required' });
    }

    // Hash password (bcrypt)
    const hashedPassword = await bcrypt.hash(String(password), 12);

    // Build payload to encrypt (your existing behavior)
    const payloadToEncrypt = {
      username: asTrimmedOrNull(username),
      email: asTrimmedOrNull(email),
      phone_country_code: asTrimmedOrNull(phone_country_code),
      phone_number: asTrimmedOrNull(phone_number),
      secuQuestion1: asTrimmedOrNull(secuQuestion1),
      secuAns1: asTrimmedOrNull(secuAns1),
      secuQuestion2: asTrimmedOrNull(secuQuestion2),
      secuAns2: asTrimmedOrNull(secuAns2),
      secuQuestion3: asTrimmedOrNull(secuQuestion3),
      secuAns3: asTrimmedOrNull(secuAns3),
      serverTimestamp: new Date().toISOString(),
      ...(clientTimestamp ? { clientTimestamp: String(clientTimestamp) } : {})
    };

    // Generate encrypted userID (existing logic)
    const encryptedUserID = encrypt(JSON.stringify(payloadToEncrypt));

    // NEW: Choose what to store in loginTable.userID
    // Priority: client-sent 'useID' -> client-sent 'userID' -> encryptedUserID
    const preferredClientID = asTrimmedOrNull(useID) || asTrimmedOrNull(clientUserID);
    const finalUserID = preferredClientID || encryptedUserID;

    // Prepare SQL + params
    const sql = `
      INSERT INTO loginTable
      (userID, username, password, email, phone_country_code, phone_number,
       secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const params = [
      finalUserID,                              // <-- will be the client 'useID' if provided
      asTrimmedOrNull(username),
      hashedPassword,
      asTrimmedOrNull(email),
      normalizeCountryCode(phone_country_code), // strips leading '+'
      asTrimmedOrNull(phone_number),
      asTrimmedOrNull(secuQuestion1),
      asTrimmedOrNull(secuAns1),
      asTrimmedOrNull(secuQuestion2),
      asTrimmedOrNull(secuAns2),
      asTrimmedOrNull(secuQuestion3),
      asTrimmedOrNull(secuAns3)
    ];

    await pool.execute(sql, params);

    // Respond with both the stored ID and the encrypted one for reference
    return res.status(201).json({
      userID: finalUserID,           // what was actually stored in DB
      encryptedUserID,               // the AES-256-CBC ID you also generate
      stored: finalUserID === encryptedUserID ? 'encrypted' : 'client-provided'
    });
  } catch (err) {
    console.error(err && err.stack ? err.stack : err);

    // Handle duplicate key (MySQL error code 1062) if userID is PK/unique
    if (err && (err.code === 'ER_DUP_ENTRY' || err.errno === 1062)) {
      return res.status(409).json({ error: 'duplicate_userID' });
    }

    const msg = err && err.message ? err.message : 'unknown_error';
    return res.status(500).json({ error: msg });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
});
