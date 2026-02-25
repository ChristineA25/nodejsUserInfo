
// routes/admin.js
'use strict';

const express = require('express');
const router = express.Router();
const { pool } = require('../db'); // mysql2/promise pool

/* ------------ OPTIONAL: Protect with an admin key (recommended) ------------
   In Railway (or .env), set: ADMIN_KEY=yourStrongSecret
   Then call with header: x-admin-key: yourStrongSecret
   If you want it fully open, delete this middleware block.
---------------------------------------------------------------------------- */
router.use((req, res, next) => {
  const required = process.env.ADMIN_KEY;
  if (!required) return next();              // no key set -> allow (dev-friendly)
  const provided = req.headers['x-admin-key'];
  if (provided !== required) {
    return res.status(403).json({ error: 'admin_key_invalid' });
  }
  next();
});

/**
 * GET /api/admin/loginTable
 * Query params: page (1-based), pageSize (default 50)
 * Example: /api/admin/loginTable?page=1&pageSize=50
 */
router.get('/loginTable', async (req, res) => {
  const ctx = { at: 'GET /api/admin/loginTable' };
  try {
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const pageSize = Math.min(Math.max(parseInt(req.query.pageSize || '50', 10), 1), 200);
    const offset = (page - 1) * pageSize;

    console.log({ ...ctx, page, pageSize, offset });

    const cols = [
      'userID',
      'username',
      'password',
      'phone_country_code',
      'secuQuestion1', 'secuAns1',
      'secuQuestion2', 'secuAns2',
      'secuQuestion3', 'secuAns3',
      'email_enc',
      'phone_number_enc',
      'monthlySalary',
      'targetMonthlySaving',
      'homeAdd',
      'workAdd',
      'displayTime'
    ].join(', ');

    // Inline LIMIT/OFFSET to avoid driver quirks with placeholders.
    const [rows] = await pool.query(
      `SELECT ${cols}
       FROM loginTable
       ORDER BY userID ASC
       LIMIT ${pageSize} OFFSET ${offset}`
    );

    // COUNT(*) with safe fallback (won't crash endpoint if COUNT fails)
    let total = 0;
    try {
      const [countRows] = await pool.query('SELECT COUNT(*) AS total FROM loginTable');
      total = Number(countRows?.[0]?.total || 0);
    } catch (countErr) {
      console.warn('COUNT fallback:', countErr?.message);
    }

    return res.json({ page, pageSize, total, rows });
  } catch (err) {
    console.error('admin/loginTable ERROR:', {
      message: err?.message, code: err?.code, stack: err?.stack
    });
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * GET /api/admin/loginTable/:userID
 * Fetch a single user row by userID
 */
router.get('/loginTable/:userID', async (req, res) => {
  const ctx = { at: 'GET /api/admin/loginTable/:userID' };
  try {
    const { userID } = req.params || {};
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const cols = [
      'userID',
      'username',
      'password',
      'phone_country_code',
      'secuQuestion1', 'secuAns1',
      'secuQuestion2', 'secuAns2',
      'secuQuestion3', 'secuAns3',
      'email_enc',
      'phone_number_enc',
      'monthlySalary',
      'targetMonthlySaving',
      'homeAdd',
      'workAdd',
      'displayTime'
    ].join(', ');

    const [rows] = await pool.query(
      `SELECT ${cols}
       FROM loginTable
       WHERE userID = ?
       LIMIT 1`,
      [String(userID)]
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'user_not_found' });
    }
    return res.json(rows[0]);
  } catch (err) {
    console.error('admin/loginTable/:userID ERROR:', {
      ...ctx, message: err?.message, code: err?.code, stack: err?.stack
    });
    return res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;
``
