
// routes/user.js
'use strict';

const express = require('express');
const axios = require('axios');
const router = express.Router();
const { pool } = require('../db'); // mysql2/promise pool

// External items service (53a4) base URL, e.g. https://nodejs-production-53a4.up.railway.app
const ITEMS_SERVICE_BASE = process.env.ITEMS_SERVICE_BASE;

const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Ensure DET_KEY is loaded from your environment variables as seen in app.js
const DET_KEY = Buffer.from(process.env.DETERMINISTIC_KEY, 'base64');

function detTokenBase64(plain) {
  if (plain === null || plain === undefined || plain === '') return null;
  const mac = crypto.createHmac('sha256', DET_KEY)
    .update(String(plain), 'utf8')
    .digest();
  return mac.toString('base64');
}

/* ------------------------------------------------------------------ */
/*                         USER BLACKLIST APIs                         */
/* ------------------------------------------------------------------ */

/**
 * GET /api/user/blacklist?userID=...
 * Return only the IDs the user has blacklisted.
 * Response: { userID, items: ["123","456", ...] }
 */
router.get('/blacklist', async (req, res) => {
  try {
    const { userID } = req.query || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const [rows] = await pool.execute(
      'SELECT itemID FROM userBlacklist WHERE userID = ? ORDER BY itemID ASC',
      [String(userID)]
    );

    const items = rows.map(r => String(r.itemID));
    return res.json({ userID: String(userID), items });
  } catch (err) {
    console.error('GET /api/user/blacklist error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * GET /api/user/blacklist/items?userID=...
 * Aggregated details: fetch IDs locally, then ask the items service for full docs.
 * Response: { userID, items: [ { id, name, ... }, ... ] }
 */
router.get('/blacklist/items', async (req, res) => {
  try {
    const { userID } = req.query || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    // 1) Get IDs from local DB
    const [rows] = await pool.execute(
      'SELECT itemID FROM userBlacklist WHERE userID = ?',
      [String(userID)]
    );
    const ids = rows.map(r => r.itemID);

    if (ids.length === 0) {
      return res.json({ userID: String(userID), items: [] });
    }

    // 2) Ask the items service (53a4) for details in bulk
    if (!ITEMS_SERVICE_BASE) {
      return res.status(500).json({ error: 'ITEMS_SERVICE_BASE_missing' });
    }

    const resp = await axios.post(
      `${ITEMS_SERVICE_BASE}/api/items/batchByIds`,
      { ids },
      {
        timeout: 8000,
        headers: { 'Content-Type': 'application/json' },
      }
    );

    const items = Array.isArray(resp?.data?.items) ? resp.data.items : [];
    return res.json({ userID: String(userID), items });
  } catch (err) {
    // If the upstream fails, surface a generic error to the client
    console.error('GET /api/user/blacklist/items aggregation error:', err?.message);
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * POST /api/user/blacklist
 * Body: { userID, itemID }
 * Idempotent via INSERT IGNORE.
 * Response: { ok: true, userID, itemID }
 */
router.post('/blacklist', async (req, res) => {
  try {
    const { userID, itemID } = req.body || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });
    if (!itemID) return res.status(400).json({ error: 'itemID_required' });

    await pool.execute(
      'INSERT IGNORE INTO userBlacklist (userID, itemID) VALUES (?, ?)',
      [String(userID), String(itemID)]
    );

    return res.status(201).json({
      ok: true,
      userID: String(userID),
      itemID: String(itemID),
    });
  } catch (err) {
    console.error('POST /api/user/blacklist error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * DELETE /api/user/blacklist/:itemID?userID=...
 * Response: { ok: true, deleted: boolean }
 */
router.delete('/blacklist/:itemID', async (req, res) => {
  try {
    const { userID } = req.query || {};
    const { itemID } = req.params || {};

    if (!userID) return res.status(400).json({ error: 'userID_required' });
    if (!itemID) return res.status(400).json({ error: 'itemID_required' });

    const [result] = await pool.execute(
      'DELETE FROM userBlacklist WHERE userID = ? AND itemID = ?',
      [String(userID), String(itemID)]
    );

    return res.json({
      ok: true,
      deleted: result.affectedRows > 0,
    });
  } catch (err) {
    console.error('DELETE /api/user/blacklist error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * PUT /api/user/blacklist
 * Replace the entire blacklist set for a user.
 * Body: { userID, items: ["123","456", ...] }
 * Response: { ok: true, userID, items: [...] }
 */
router.put('/blacklist', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { userID, items } = req.body || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const arr = Array.isArray(items)
      ? items.map(x => String(x)).filter(Boolean)
      : [];

    await conn.beginTransaction();

    // Clear existing rows
    await conn.execute('DELETE FROM userBlacklist WHERE userID = ?', [
      String(userID),
    ]);

    // Bulk insert new set
    if (arr.length > 0) {
      const values = arr.map(itemID => [String(userID), String(itemID)]);
      // mysql2/promise: bulk values with .query([...])
      await conn.query(
        'INSERT INTO userBlacklist (userID, itemID) VALUES ?',
        [values]
      );
    }

    await conn.commit();

    return res.json({
      ok: true,
      userID: String(userID),
      items: arr,
    });
  } catch (err) {
    try {
      await conn.rollback();
    } catch (_) {}
    console.error('PUT /api/user/blacklist error:', err);
    return res.status(500).json({ error: 'server_error' });
  } finally {
    conn.release();
  }
});

// Add these requires if they aren't at the top of your route file
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

router.put('/update-credentials', async (req, res) => {
  try {
    const { 
      userID, 
      newPassword, 
      phone_country_code, 
      email, 
      phone_number 
    } = req.body;

    if (!userID) return res.status(400).json({ error: 'userID_required' });

    // 1. Password Hashing (12 rounds as per app.js)
    const passwordHash = newPassword ? await bcrypt.hash(String(newPassword), 12) : null;

    // 2. Encryption Helper (must match app.js DET_KEY logic)
    const encrypt = (val) => {
      if (!val) return null;
      const key = Buffer.from(process.env.DETERMINISTIC_KEY, 'base64');
      return crypto.createHmac('sha256', key).update(String(val).trim().toLowerCase()).digest('base64');
    };

    const emailEnc = email ? encrypt(email) : null;
    const phoneEnc = phone_number ? encrypt(phone_number) : null;
    const countryCode = phone_country_code || null;

    // 3. Update Database
    const sql = `
      UPDATE loginTable 
      SET 
        password = COALESCE(?, password), 
        phone_country_code = ?, 
        email_enc = ?, 
        phone_number_enc = ? 
      WHERE userID = ?`;

    const [result] = await pool.execute(sql, [passwordHash, countryCode, emailEnc, phoneEnc, String(userID)]);

    if (result.affectedRows === 0) return res.status(404).json({ error: 'user_not_found' });

    return res.json({ ok: true, message: 'Credentials updated' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;
