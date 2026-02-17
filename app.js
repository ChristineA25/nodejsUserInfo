
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

require('dotenv').config();
const userRouter = require('./routes/user');

app.use('/api/user', userRouter);


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


// f031/app.js
app.get('/api/user/blacklist/items', async (req, res) => {
  try {
    const { userID } = req.query || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const sql = `
      SELECT i.id, i.name, i.brand, i.quantity, i.feature, i.productColor, i.picWebsite
      FROM userBlacklist ub
      JOIN item i ON i.id = ub.itemID
      WHERE ub.userID = ?
      ORDER BY i.name ASC
    `;
    const [rows] = await pool.execute(sql, [String(userID)]);
    res.json({ userID: String(userID), items: rows });
  } catch (err) {
    res.status(500).json({ error: 'server_error' });
  }
});


/* ------------------------------------------------------------------ */
/*                        API: USER BLACKLIST                          */
/* ------------------------------------------------------------------ */

/**
 * Shape conventions (consistent with your other APIs):
 *  - 400 for missing params / invalid input
 *  - 404 when user not found is NOT checked here (we store by userID key)
 *  - 201 on single insert success
 *  - 200 on GET/PUT/DELETE success
 *  - { error: '...' } for error payloads
 */


const axios = require('axios'); // npm i axios

// GET /api/user/blacklist/items  (API-aggregated)
app.get('/api/user/blacklist/items', async (req, res) => {
  try {
    const { userID } = req.query || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    // 1) Get IDs from our local DB (which has userBlacklist)
    const [rows] = await pool.execute(
      'SELECT itemID FROM userBlacklist WHERE userID = ?',
      [String(userID)]
    );
    const ids = rows.map(r => r.itemID);

    if (ids.length === 0) return res.json({ userID: String(userID), items: [] });

    // 2) Ask the items service (53a4) for details
    const base = process.env.ITEMS_SERVICE_BASE; // e.g., https://nodejs-production-53a4.up.railway.app
    const resp = await axios.post(`${base}/api/items/batchByIds`, { ids }, {
      timeout: 8000,
      headers: { 'Content-Type': 'application/json' },
    });

    // 3) Return items to the client
    return res.json({ userID: String(userID), items: resp.data.items || [] });
  } catch (err) {
    console.error('GET /api/user/blacklist/items aggregation error:', err.message);
    return res.status(500).json({ error: 'server_error' });
  }
});


// GET all blacklisted itemIDs for a user
app.get('/api/user/blacklist', async (req, res) => {
  try {
    const { userID } = req.query || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const [rows] = await pool.execute(
      'SELECT itemID FROM userBlacklist WHERE userID = ? ORDER BY itemID ASC',
      [userID]
    );
    const items = rows.map(r => String(r.itemID));
    return res.json({ userID, items });
  } catch (err) {
    console.error('GET /api/user/blacklist error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Add ONE blacklisted item
app.post('/api/user/blacklist', async (req, res) => {
  try {
    const { userID, itemID } = req.body || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });
    if (!itemID) return res.status(400).json({ error: 'itemID_required' });

    // INSERT IGNORE to be idempotent if (userID,itemID) already exists
    await pool.execute(
      'INSERT IGNORE INTO userBlacklist (userID, itemID) VALUES (?, ?)',
      [String(userID), String(itemID)]
    );

    return res.status(201).json({ ok: true, userID: String(userID), itemID: String(itemID) });
  } catch (err) {
    console.error('POST /api/user/blacklist error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Delete ONE blacklisted item for a user
app.delete('/api/user/blacklist/:itemID', async (req, res) => {
  try {
    const { userID } = req.query || {};
    const { itemID } = req.params || {};

    if (!userID) return res.status(400).json({ error: 'userID_required' });
    if (!itemID) return res.status(400).json({ error: 'itemID_required' });

    const [result] = await pool.execute(
      'DELETE FROM userBlacklist WHERE userID = ? AND itemID = ?',
      [String(userID), String(itemID)]
    );

    return res.json({ ok: true, deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/user/blacklist error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Replace ENTIRE blacklist set for a user (bulk update)
app.put('/api/user/blacklist', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { userID, items } = req.body || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const arr = Array.isArray(items) ? items.map(x => String(x)).filter(Boolean) : [];

    await conn.beginTransaction();

    // Clear existing
    await conn.execute('DELETE FROM userBlacklist WHERE userID = ?', [String(userID)]);

    // Insert new set (if any)
    if (arr.length > 0) {
      const values = arr.map(itemID => [String(userID), String(itemID)]);
      // Bulk insert
      await conn.query(
        'INSERT INTO userBlacklist (userID, itemID) VALUES ?',
        [values]
      );
    }

    await conn.commit();
    return res.json({ ok: true, userID: String(userID), items: arr });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    console.error('PUT /api/user/blacklist error:', err);
    return res.status(500).json({ error: 'server_error' });
  } finally {
    conn.release();
  }
});


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
/*                         API: USER ALLERGENS                         */
/* ------------------------------------------------------------------ */

// GET all allergens for a user
app.get('/api/user/allergens', async (req, res) => {
  try {
    const { userID } = req.query || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const [rows] = await pool.execute(
      'SELECT allergenID FROM userAllergen WHERE userID = ? ORDER BY allergenID ASC',
      [userID]
    );
    const items = rows.map(r => String(r.allergenID));
    return res.json({ userID, items });
  } catch (err) {
    console.error('GET /api/user/allergens error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Add one allergen (insert)
app.post('/api/user/allergens', async (req, res) => {
  try {
    const { userID, allergenID } = req.body || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });
    if (!allergenID) return res.status(400).json({ error: 'allergenID_required' });

    await pool.execute(
      'INSERT IGNORE INTO userAllergen (userID, allergenID) VALUES (?, ?)',
      [userID, String(allergenID)]
    );
    return res.status(201).json({ ok: true, userID, allergenID: String(allergenID) });
  } catch (err) {
    console.error('POST /api/user/allergens error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Delete one allergen (remove)
app.delete('/api/user/allergens/:allergenID', async (req, res) => {
  try {
    const { userID } = req.query || {};
    const { allergenID } = req.params || {};

    if (!userID) return res.status(400).json({ error: 'userID_required' });
    if (!allergenID) return res.status(400).json({ error: 'allergenID_required' });

    const [result] = await pool.execute(
      'DELETE FROM userAllergen WHERE userID = ? AND allergenID = ?',
      [userID, String(allergenID)]
    );
    return res.json({ ok: true, deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/user/allergens error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Replace entire allergen set (bulk update)
app.put('/api/user/allergens', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { userID, items } = req.body || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const arr = Array.isArray(items) ? items.map(x => String(x)) : [];

    await conn.beginTransaction();

    await conn.execute('DELETE FROM userAllergen WHERE userID = ?', [userID]);

    if (arr.length > 0) {
      const values = arr.map(a => [userID, a]);
      await conn.query(
        'INSERT INTO userAllergen (userID, allergenID) VALUES ?',
        [values]
      );
    }

    await conn.commit();
    return res.json({ ok: true, userID, items: arr });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    console.error('PUT /api/user/allergens error:', err);
    return res.status(500).json({ error: 'server_error' });
  } finally {
    conn.release();
  }
});


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
