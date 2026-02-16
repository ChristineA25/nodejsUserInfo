
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
app.use(express.json({ limit: '10kb' }));

/* ------------------------------------------------------------------ */
/*                          Key Management                             */
/* ------------------------------------------------------------------ */
function loadKeyFromEnv(envName, expectedLen) {
  const b64 = process.env[envName];
  if (!b64) throw new Error(`${envName}_missing`);
  const buf = Buffer.from(b64, 'base64');
  if (buf.length !== expectedLen) {
    throw new Error(`${envName}_must_be_${expectedLen}_bytes_base64`);
  }
  return buf;
}

let DET_KEY;
try {
  DET_KEY = loadKeyFromEnv('DETERMINISTIC_KEY', 32);
} catch (e) {
  console.warn('⚠️ Key load warning:', e.message);
}

/* ------------------------------------------------------------------ */
/*                      Deterministic “Tokenization”                   */
/* ------------------------------------------------------------------ */
function detTokenBase64(plain) {
  if (plain === null || plain === undefined) return null;
  if (!DET_KEY) throw new Error('DETERMINISTIC_KEY_missing');
  const mac = crypto.createHmac('sha256', DET_KEY)
    .update(String(plain), 'utf8')
    .digest();
  return mac.toString('base64');
}

/* ------------------------------------------------------------------ */
/*                      Normalization Helpers                          */
/* ------------------------------------------------------------------ */
function normalizeEmail(email) {
  if (!email) return null;
  return String(email).trim().toLowerCase();
}

function buildE164({ phoneE164, phone_country_code, phone_number }) {
  const isValidE164 = (v) => typeof v === 'string' && /^\+\d{6,15}$/.test(v);

  if (isValidE164(phoneE164)) return phoneE164;

  const ccRaw = (phone_country_code || '').toString().trim();
  const localRaw = (phone_number || '').toString().trim();

  if (!ccRaw.startsWith('+')) throw new Error('invalid_country_code');

  const ccDigits = ccRaw.replace(/[^\d]/g, '');
  const localDigits = localRaw.replace(/\D+/g, '');

  const combined = `+${ccDigits}${localDigits}`;
  if (!isValidE164(combined)) throw new Error('invalid_e164_combination');
  return combined;
}

/* ------------------------------------------------------------------ */
/*                         Health & Static                             */
/* ------------------------------------------------------------------ */
app.get('/health', (req, res) => res.status(200).send('ok'));
app.use(express.static(path.join(__dirname, 'public')));

/* Routes Mount */
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
app.post('/api/signup', async (req, res) => {
  try {
    const {
      userID,
      identifierType,
      username, password, email,
      phone_country_code, phone_number, phoneE164,
      secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3
    } = req.body || {};

    if (!userID)    return res.status(400).json({ error: 'userID_required' });
    if (!password)  return res.status(400).json({ error: 'password_required' });

    if (identifierType === 'username' && !username)
      return res.status(400).json({ error: 'username_required' });

    if (identifierType === 'email' && !email)
      return res.status(400).json({ error: 'email_required' });

    if (identifierType === 'phone' && !phone_number && !phoneE164)
      return res.status(400).json({ error: 'phone_number_required' });

    const passwordHash = await bcrypt.hash(String(password), 12);

    // Deterministic tokens
    let emailEnc = null;
    let phoneEnc = null;
    let phoneE164Final = null;

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
      return res.status(500).json({ error: tokErr.message });
    }

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
      emailEnc,
      phoneEnc
    ];

    const [result] = await pool.execute(sql, params);
    return res.status(201).json({ userID });

  } catch (err) {
    const msg  = (err && err.message) ? err.message : 'unknown_error';
    const code = (err && err.code)    ? err.code    : null;

    if (code === 'ER_DUP_ENTRY') {
      const raw = (err.sqlMessage || err.message || '').toLowerCase();
      let field = 'identifier';
      if (raw.includes('email_enc')) field = 'email';
      else if (raw.includes('phone_number_enc')) field = 'phone';
      else if (raw.includes('username')) field = 'username'; // if UNIQUE(username) exists
      else if (raw.includes('secuans1') || raw.includes('secuans2') || raw.includes('secuans3')) field = 'security answer';
      const message = `${field} already in use. Please use another or use other provided options to sign up`;
      return res.status(409).json({ error: 'duplicate_identifier', field, message });
    }

    return res.status(500).json({ error: msg });
  }
});


/* ------------------------------------------------------------------ */
/*                             API: LOGIN                              */
/* ------------------------------------------------------------------ */
app.post('/api/login', async (req, res) => {
  try {
    const {
      identifier,        // email OR username OR raw phone digits
      password,
      phone_country_code,
      phone_number,
      phoneE164,
      identifierType     // NEW (optional): "email" | "phone" | "username"
    } = req.body || {};

    if (!identifier)
      return res.status(400).json({ error: 'identifier_required' });

    if (!password)
      return res.status(400).json({ error: 'password_required' });

    let where = '';
    let value = null;

    // If the client tells us the identifier type, use that path.
    // Otherwise, fall back to the original auto-detect logic.
    const explicit = (identifierType || '').toString().trim().toLowerCase();

    if (explicit === 'email') {
      const norm = normalizeEmail(identifier);
      const emailEnc = detTokenBase64(norm);
      where = 'email_enc = ?';
      value = emailEnc;

    } else if (explicit === 'phone') {
      let e164Final;
      try {
        e164Final = buildE164({
          phoneE164,
          phone_country_code,
          phone_number: phone_number || identifier // allow raw digits as identifier
        });
      } catch (err) {
        return res.status(400).json({ error: 'invalid_phone_number' });
      }
      const phoneEnc = detTokenBase64(e164Final);
      where = 'phone_number_enc = ?';
      value = phoneEnc;

    } else if (explicit === 'username') {
      where = 'username = ?';
      value = identifier;

    } else {
      // --- Fallback: original auto-detect ---
      if (identifier.includes('@')) {
        const norm = normalizeEmail(identifier);
        const emailEnc = detTokenBase64(norm);
        where = 'email_enc = ?';
        value = emailEnc;

      } else if (/^[\d+]+$/.test(identifier)) {
        let e164Final;
        try {
          e164Final = buildE164({
            phoneE164,
            phone_country_code,
            phone_number: phone_number || identifier
          });
        } catch (err) {
          return res.status(400).json({ error: 'invalid_phone_number' });
        }
        const phoneEnc = detTokenBase64(e164Final);
        where = 'phone_number_enc = ?';
        value = phoneEnc;

      } else {
        where = 'username = ?';
        value = identifier;
      }
    }

    const sql = `
      SELECT userID, username, password
      FROM loginTable
      WHERE ${where}
      LIMIT 1
    `;
    const [rows] = await pool.execute(sql, [value]);

    if (!rows || rows.length === 0)
      return res.status(404).json({ error: 'identifier_not_found' });

    const user = rows[0];

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ error: 'invalid_password' });

    return res.status(200).json({
      userID: user.userID,
      username: user.username || null
    });

  } catch (err) {
    console.error('LOGIN ERROR:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});


/* ------------------------------------------------------------------ */
/*                         API: USER SETTINGS                          */
/* ------------------------------------------------------------------ */
app.get('/api/user/settings', async (req, res) => {
  try {
    const { userID } = req.query || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const [rows] = await pool.execute(
      `SELECT userID, monthlySalary, targetMonthlySaving, homeAddCode, workAddCode
         FROM loginTable
        WHERE userID = ?
        LIMIT 1`,
      [userID]
    );

    if (!rows || rows.length === 0)
      return res.status(404).json({ error: 'user_not_found' });

    const r = rows[0];
    // MySQL may return DECIMAL as strings; normalize to numbers where possible.
    const num = (v) => (v === null || v === undefined ? null : Number(v));

    return res.json({
      userID: r.userID,
      monthlySalary: num(r.monthlySalary),
      targetMonthlySaving: num(r.targetMonthlySaving),
      homeAddCode: r.homeAddCode || null,
      workAddCode: r.workAddCode || null
    });
  } catch (err) {
    console.error('GET /api/user/settings error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

app.put('/api/user/settings', async (req, res) => {
  try {
    const {
      userID,
      monthlySalary,
      targetMonthlySaving,
      homeAddCode,
      workAddCode
    } = req.body || {};

    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const toNum = (v) => (v === '' || v === null || v === undefined ? null : Number(v));
    const msNum = toNum(monthlySalary);
    const tsNum = toNum(targetMonthlySaving);

    if (msNum !== null && (Number.isNaN(msNum) || msNum < 0))
      return res.status(400).json({ error: 'invalid_monthlySalary' });

    if (tsNum !== null && (Number.isNaN(tsNum) || tsNum < 0))
      return res.status(400).json({ error: 'invalid_targetMonthlySaving' });

    const [result] = await pool.execute(
      `UPDATE loginTable
          SET monthlySalary = ?,
              targetMonthlySaving = ?,
              homeAddCode = ?,
              workAddCode = ?
        WHERE userID = ?`,
      [msNum, tsNum, homeAddCode ?? null, workAddCode ?? null, userID]
    );

    if (result.affectedRows === 0)
      return res.status(404).json({ error: 'user_not_found' });

    return res.json({
      ok: true,
      userID,
      monthlySalary: msNum,
      targetMonthlySaving: tsNum,
      homeAddCode: homeAddCode ?? null,
      workAddCode: workAddCode ?? null
    });
  } catch (err) {
    console.error('PUT /api/user/settings error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

/* ------------------------------------------------------------------ */
/*                        404 & Server Listen                          */
/* ------------------------------------------------------------------ */
app.use((req, res) => {
  const fallback404 = path.join(__dirname, 'views', '404.html');
  res.status(404).sendFile(fallback404, (sendErr) => {
    if (sendErr)
      res.status(404).type('text').send('404 – Not Found');
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
  if (!indexRouterMounted) {
    console.warn('⚠️ indexRouter was not mounted. Only static files and /health + /api/signup are active.');
  }
});
