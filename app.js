
// Only load .env during local development
if (process.env.NODE_ENV !== 'production') {
  try {
    require('dotenv').config();
  } catch (_) {}
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
/* Key Management */
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
/* Deterministic “Tokenization” */
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
/* Normalization Helpers */
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
  const ccDigits = ccRaw.replace(/\D+/g, '');
  const localDigits = localRaw.replace(/\D+/g, '');
  const combined = `+${ccDigits}${localDigits}`;
  if (!isValidE164(combined)) throw new Error('invalid_e164_combination');
  return combined;
}

/* ------------------------------------------------------------------ */
/* API: USER BLACKLIST */
/* ------------------------------------------------------------------ */
/**
 * GET /api/user/blacklist?userID=...
 * Return only the IDs the user has blacklisted.
 */
app.get('/api/user/blacklist', async (req, res) => {
  try {
    const { userID } = req.query || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });
    const [rows] = await pool.execute(
      'SELECT itemID FROM userBlacklist WHERE userID = ? ORDER BY itemID ASC',
      [String(userID)]
    );
    const items = rows.map((r) => String(r.itemID));
    return res.json({ userID: String(userID), items });
  } catch (err) {
    console.error('GET /api/user/blacklist error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});


async function getRegionIdFromPhoneCode(phoneCountryCode) {
  if (!phoneCountryCode) return null;

  const [rows] = await pool.execute(
    `SELECT regionID
     FROM phoneInfo
     WHERE regionPhoneCode = ?
     LIMIT 1`,
    [phoneCountryCode]
  );

  return rows.length > 0 ? rows[0].regionID : null;
}

/**
 * POST /api/user/blacklist
 * Body: { userID, itemID }
 * Idempotent via INSERT IGNORE.
 */
app.post('/api/user/blacklist', async (req, res) => {
  try {
    const { userID, itemID } = req.body || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });
    if (!itemID) return res.status(400).json({ error: 'itemID_required' });
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

/**
 * DELETE /api/user/blacklist/:itemID?userID=...
 */
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

/**
 * PUT /api/user/blacklist
 * Replace the entire blacklist set for a user.
 * Body: { userID, items: ["123", "456", ...] }
 */
app.put('/api/user/blacklist', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { userID, items } = req.body || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const arr = Array.isArray(items) ? items.map((x) => String(x)).filter(Boolean) : [];

    await conn.beginTransaction();
    await conn.execute('DELETE FROM userBlacklist WHERE userID = ?', [String(userID)]);

    if (arr.length > 0) {
      const values = arr.map((itemID) => [String(userID), String(itemID)]);
      // NOTE: For mysql2 you must expand placeholders; keeping your original behavior,
      // but if this ever errors, swap to a generated "(?, ?), ..." string + flat params.
      await conn.query('INSERT INTO userBlacklist (userID, itemID) VALUES ?', [values]);
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
/* Health & Static */
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
/* API: USER ALLERGENS */
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
    const items = rows.map((r) => String(r.allergenID));
    return res.json({ userID, items });
  } catch (err) {
    console.error('GET /api/user/allergens error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Add one allergen
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

// Delete one allergen
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

// Replace entire allergen set
app.put('/api/user/allergens', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { userID, items } = req.body || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const arr = Array.isArray(items) ? items.map((x) => String(x)) : [];

    await conn.beginTransaction();
    await conn.execute('DELETE FROM userAllergen WHERE userID = ?', [userID]);

    if (arr.length > 0) {
      const values = arr.map((a) => [userID, a]);
      await conn.query('INSERT INTO userAllergen (userID, allergenID) VALUES ?', [values]);
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


let displayTime = null;

if (identifierType === 'phone') {
  displayTime = await getRegionIdFromPhoneCode(phone_country_code);
}

/* ------------------------------------------------------------------ */
/* API: Signup */
/* ------------------------------------------------------------------ */

app.post('/api/signup', async (req, res) => {
  try {
    const {
      userID,
      identifierType,
      username,
      password,
      email,
      phone_country_code,
      phone_number,
      phoneE164,
      secuQuestion1, secuAns1,
      secuQuestion2, secuAns2,
      secuQuestion3, secuAns3
    } = req.body || {};

    if (!userID) return res.status(400).json({ error: 'userID_required' });
    if (!password) return res.status(400).json({ error: 'password_required' });

    if (identifierType === 'username' && !username)
      return res.status(400).json({ error: 'username_required' });

    if (identifierType === 'email' && !email)
      return res.status(400).json({ error: 'email_required' });

    if (identifierType === 'phone' && !phone_number && !phoneE164)
      return res.status(400).json({ error: 'phone_required' });

    const passwordHash = await bcrypt.hash(String(password), 12);

    let emailEnc = null;

    let phoneEnc = null;
    let displayTime = null;

    if (email) {
      emailEnc = detTokenBase64(normalizeEmail(email));
    }

    if (identifierType === 'phone') {
      const e164 = buildE164({ phoneE164, phone_country_code, phone_number });
      phoneEnc = detTokenBase64(e164);

      // ✅ SET displayTime BASED ON PHONE COUNTRY CODE
      displayTime = await getRegionIdFromPhoneCode(phone_country_code);
    }

    const sql = `
      INSERT INTO loginTable (
        userID,
        username,
        password,
        phone_country_code,
        secuQuestion1, secuAns1,
        secuQuestion2, secuAns2,
        secuQuestion3, secuAns3,
        email_enc,
        phone_number_enc,
        displayTime
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      phoneEnc,
      displayTime
    ];

    await pool.execute(sql, params);

    return res.status(201).json({ userID });

  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        error: 'duplicate',
        message: 'Username, email, phone, or security answer already in use'
      });
    }
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

/* ------------------------------------------------------------------ */
/* API: LOGIN */
/* ------------------------------------------------------------------ */
app.post('/api/login', async (req, res) => {
  try {
    const {
      identifier, // email OR username OR raw phone digits
      password,
      phone_country_code,
      phone_number,
      phoneE164,
      identifierType // optional: "email" | "phone" | "username"
    } = req.body || {};

    if (!identifier)
      return res.status(400).json({ error: 'identifier_required' });
    if (!password)
      return res.status(400).json({ error: 'password_required' });

    let where = '';
    let value = null;

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
          phone_number: phone_number || identifier
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
      // --- Fallback: auto-detect ---
      if (identifier.includes('@')) {
        const norm = normalizeEmail(identifier);
        const emailEnc = detTokenBase64(norm);
        where = 'email_enc = ?';
        value = emailEnc;
      } else if (/^\d+$/.test(identifier)) {
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
/* API: USER SETTINGS */
/* ------------------------------------------------------------------ */
// READ settings
app.get('/api/user/settings', async (req, res) => {
  try {
    const { userID } = req.query || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const [rows] = await pool.execute(
      `SELECT userID, monthlySalary, targetMonthlySaving, homeAdd, workAdd
       FROM loginTable
       WHERE userID = ?
       LIMIT 1`,
      [userID]
    );

    if (!rows || rows.length === 0)
      return res.status(404).json({ error: 'user_not_found' });

    const r = rows[0];
    const num = (v) => (v === null || v === undefined ? null : Number(v));

    return res.json({
      userID: r.userID,
      monthlySalary: num(r.monthlySalary),
      targetMonthlySaving: num(r.targetMonthlySaving),
      homeAdd: r.homeAdd || null,
      workAdd: r.workAdd || null
    });
  } catch (err) {
    console.error('GET /api/user/settings error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// UPDATE settings
app.put('/api/user/settings', async (req, res) => {
  try {
    const {
      userID,
      monthlySalary,
      targetMonthlySaving,
      homeAdd, // new column name (TEXT)
      workAdd, // new column name (TEXT)
      // Legacy body field names from old clients (ignored if new ones present)
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

    // Backward compatibility
    const homeAddFinal = (homeAdd !== undefined) ? homeAdd : (homeAddCode ?? null);
    const workAddFinal = (workAdd !== undefined) ? workAdd : (workAddCode ?? null);

    const [result] = await pool.execute(
      `UPDATE loginTable
       SET monthlySalary = ?,
           targetMonthlySaving = ?,
           homeAdd = ?,
           workAdd = ?
       WHERE userID = ?`,
      [msNum, tsNum, homeAddFinal ?? null, workAddFinal ?? null, userID]
    );

    await pool.execute(
      `INSERT INTO salaryHist (userID, salary, targetSaving, changedAt) 
       VALUES (?, ?, ?, NOW())`,
      [userID, msNum, tsNum]
    );

    if (result.affectedRows === 0)
      return res.status(404).json({ error: 'user_not_found' });

    return res.json({
      ok: true,
      userID,
      monthlySalary: msNum,
      targetMonthlySaving: tsNum,
      homeAdd: homeAddFinal ?? null,
      workAdd: workAddFinal ?? null
    });
  } catch (err) {
    console.error('PUT /api/user/settings error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});


// UPDATE displayTime for a user
app.put('/api/user/displayTime', async (req, res) => {
  try {
    const { userID, displayTime } = req.body ?? {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    // Accept either a literal string (e.g., "19:36,11feb26") or an ISO datetime.
    // If you have control over the client, prefer ISO-8601 for consistency.
    const value =
      displayTime === undefined || displayTime === null || displayTime === ''
        ? null
        : String(displayTime).trim();

    const [result] = await pool.execute(
      'UPDATE loginTable SET displayTime = ? WHERE userID = ?',
      [value, String(userID)]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'user_not_found' });
    }
    return res.json({ ok: true, userID: String(userID), displayTime: value });
  } catch (err) {
    console.error('PUT /api/user/displayTime error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * API: Admin Update User Password
 * PUT /api/admin/update-password
 * Body: { userID, newPassword }
 */
app.put('/api/admin/update-password', async (req, res) => {
  try {
    const { userID, newPassword } = req.body || {};

    if (!userID) return res.status(400).json({ error: 'userID_required' });
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'password_too_short' });
    }

    // Hash the password with 12 rounds to match existing records
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(String(newPassword), saltRounds);

    const sql = 'UPDATE loginTable SET password = ? WHERE userID = ?';
    const [result] = await pool.execute(sql, [passwordHash, String(userID)]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    return res.json({ ok: true, message: 'Password updated successfully' });
  } catch (err) {
    console.error('Update Password Error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * PUT /api/user/update-identity
 * Updates sensitive fields using the correct hashing and encryption methods.
 * Supports setting fields to null.
 */
app.put('/api/user/update-identity', async (req, res) => {
  try {
    const {
      userID,
      username,
      password,
      phone_country_code,
      email,
      phone_number,
      phoneE164
    } = req.body || {};

    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const updates = [];
    const params = [];

    // 1. Username (Plain text or Null)
    if (username !== undefined) {
      updates.push('username = ?');
      params.push(username);
    }

    // 2. Password (Bcrypt Hash or Null)
    if (password !== undefined) {
      updates.push('password = ?');
      const hash = password === null ? null : await bcrypt.hash(String(password), 12);
      params.push(hash);
    }

    // 3. Phone Country Code (Plain text or Null)
    if (phone_country_code !== undefined) {
      updates.push('phone_country_code = ?');
      params.push(phone_country_code);
    }

    // 4. Email (Deterministic Encryption or Null)
    if (email !== undefined) {
      updates.push('email_enc = ?');
      const normEmail = normalizeEmail(email);
      const emailEnc = normEmail ? detTokenBase64(normEmail) : null;
      params.push(emailEnc);
    }

    // 5. Phone Number (Deterministic Encryption or Null)
    if (phone_number !== undefined || phoneE164 !== undefined) {
      updates.push('phone_number_enc = ?');
      try {
        if (phone_number === null && (phoneE164 === null || phoneE164 === undefined)) {
          params.push(null);
        } else {
          const e164 = buildE164({ phoneE164, phone_country_code, phone_number });
          params.push(detTokenBase64(e164));
        }
      } catch (e) {
        return res.status(400).json({ error: 'invalid_phone_format' });
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'no_fields_to_update' });
    }

    const sql = `UPDATE loginTable SET ${updates.join(', ')} WHERE userID = ?`;
    params.push(String(userID));

    const [result] = await pool.execute(sql, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    return res.json({ ok: true, message: 'Identity updated' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'duplicate_entry', message: 'Username, email, or phone already exists' });
    }
    console.error('Update Identity Error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// After other app.use(...) and router mounts
try {
  const adminRouter = require('./routes/admin');
  app.use('/api/admin', adminRouter);
  console.log('✅ adminRouter mounted at /api/admin');
} catch (err) {
  console.error('❌ Failed to load ./routes/admin:', err.message);
}

/* ------------------------------------------------------------------ */
/* 404 & Server Listen */
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
});
