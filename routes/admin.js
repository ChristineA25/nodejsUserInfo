
// routes/admin.js
'use strict';

const express = require('express');
const router = express.Router();
const { pool } = require('../db'); // mysql2/promise pool

// Dev-only safety guard: expose these endpoints only outside production.
// Remove this block if you explicitly need them in production.
/*
router.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'disabled_in_production' });
  }
  next();
});
*/

/**
 * GET /api/admin/loginTable
 * Fetch a page of rows with the columns visible in your screenshots.
 * Query params: page (1-based), pageSize (default 50)
 * Example: /api/admin/loginTable?page=1&pageSize=50
 */
router.get('/loginTable', async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const pageSize = Math.min(Math.max(parseInt(req.query.pageSize || '50', 10), 1), 200);
    const offset = (page - 1) * pageSize;

    // Select only the columns shown in your screenshots
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

    const [rows] = await pool.execute(
      `SELECT ${cols}
       FROM loginTable
       ORDER BY userID ASC
       LIMIT ? OFFSET ?`,
      [pageSize, offset]
    );

    // Optionally return a count for client paging
    const [[{ total }]] = await pool.query('SELECT COUNT(*) AS total FROM loginTable');

    return res.json({
      page,
      pageSize,
      total,
      rows
    });
  } catch (err) {
    console.error('GET /api/admin/loginTable error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * GET /api/admin/loginTable/:userID
 * Fetch a single user row by userID
 */
router.get('/loginTable/:userID', async (req, res) => {
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

    const [rows] = await pool.execute(
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
    console.error('GET /api/admin/loginTable/:userID error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;
