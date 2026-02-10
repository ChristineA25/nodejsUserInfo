
// ---- AES-256-GCM helpers ----
const crypto = require('crypto');

function getFieldKey() {
  const b64 = process.env.FIELD_ENC_KEY || '';
  const key = Buffer.from(b64, 'base64'); // must decode to 32 bytes
  if (key.length !== 32) {
    throw new Error('FIELD_ENC_KEY must be a base64-encoded 32-byte key (AES-256)');
  }
  return key;
}

function encryptField(plain) {
  if (plain == null) return null;
  const key = getFieldKey();
  const iv = crypto.randomBytes(12); // 96-bit nonce
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}:${tag.toString('base64')}:${enc.toString('base64')}`;
}

// Optional (for admin/readbacks)
function decryptField(packed) {
  if (!packed) return null;
  const [ivB64, tagB64, dataB64] = String(packed).split(':');
  const key = getFieldKey();
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const data = Buffer.from(dataB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString('utf8');
}

// app.js
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');            // make sure bcryptjs is in dependencies
const { pool } = require('./db');              // db.js must export a mysql2/promise pool

const app = express();

// Parse JSON (needed for req.body)
app.use(express.json());

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
 *   "userID": 2,
 *   "username": "railway_test",
 *   "password": "Passw0rd!123",
 *   "email": "railway@example.com",
 *   "phone_country_code": "+44",
 *   "phone_number": "07123456789",
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
      identifierType,     // "username" | "email" | "phone" (from Flutter)
      username,
      email,              // plaintext email from client
      phone_country_code, // KEEP EXACTLY AS SENT, e.g., "+44"
      phone_number,       // local digits only from client
      password,
      secuQuestion1, secuAns1,
      secuQuestion2, secuAns2,
      secuQuestion3, secuAns3,
    } = req.body || {};

    // --- basic checks ---
    if (userID === undefined || userID === null || userID === '') {
      return res.status(400).json({ error: 'userID_required' });
    }
    if (!password) {
      return res.status(400).json({ error: 'password_required' });
    }

    // Optional: ensure a coherent mode
    const idType = String(identifierType || '').toLowerCase();
    if (idType && !['username','email','phone'].includes(idType)) {
      return res.status(400).json({ error: 'identifierType_invalid' });
    }

    // --- build plaintext + encrypted shadows ---
    let usernameToStore = null;
    let emailPlain = null, emailEnc = null;
    let phoneCodeRaw = null, phoneLocalPlain = null, phoneLocalEnc = null;

    if (idType === 'username') {
      if (!username) return res.status(400).json({ error: 'username_required' });
      usernameToStore = String(username).trim();
    }

    if (idType === 'email' || (!idType && email)) {
      if (!email) return res.status(400).json({ error: 'email_required' });
      emailPlain = String(email).trim();     // stays plaintext for checks/UI
      emailEnc   = encryptField(emailPlain); // encrypted shadow
    }

    if (idType === 'phone' || (!idType && phone_country_code && phone_number)) {
      if (!phone_country_code) return res.status(400).json({ error: 'phone_country_code_required' });
      // DO NOT STRIP '+' — store exactly as user typed
      phoneCodeRaw = String(phone_country_code); // e.g., "+44"

      if (!phone_number || !/^\d+$/.test(String(phone_number))) {
        return res.status(400).json({ error: 'phone_number_digits_only' });
      }
      phoneLocalPlain = String(phone_number).trim();  // plaintext for UI/queries
      if (phoneLocalPlain.length < 4 || phoneLocalPlain.length > 14) {
        return res.status(400).json({ error: 'phone_number_invalid_length' });
      }
      phoneLocalEnc = encryptField(phoneLocalPlain);  // encrypted shadow
    }

    // --- hash password ---
    const hashed = await bcrypt.hash(String(password), 12);

    // --- INSERT with both plaintext + encrypted shadows ---
    const sql = `
      INSERT INTO loginTable
        (userID, username, password,
         email, email_enc,
         phone_country_code, phone_number, phone_number_enc,
         secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
      userID,
      usernameToStore,
      hashed,
      emailPlain,
      emailEnc,
      phoneCodeRaw,       // <-- EXACT form input (e.g., "+44")
      phoneLocalPlain,    // <-- plaintext digits
      phoneLocalEnc,      // <-- encrypted shadow
      secuQuestion1 ?? null, secuAns1 ?? null,
      secuQuestion2 ?? null, secuAns2 ?? null,
      secuQuestion3 ?? null, secuAns3 ?? null,
    ];

    await pool.execute(sql, params);
    return res.status(201).json({ userID });
  } catch (err) {
    if (err && err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'duplicate_identifier' });
    }
    console.error('signup error:', err?.message || err);
    return res.status(500).json({ error: 'server_error' });
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
