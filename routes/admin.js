
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


// === DROP-IN: routes/admin.js additions =====================================
const stringifyCsv = (rows) => {
  if (!rows || rows.length === 0) return 'userID,allergenID\n';
  const header = 'userID,allergenID\n';
  const body = rows
    .map(r => `${String(r.userID)},${String(r.allergenID)}`)
    .join('\n');
  return header + body + '\n';
};

/**
 * GET /api/admin/userAllergen
 * Returns ALL rows from userAllergen with optional filters and pagination.
 * Query params:
 *   - userID: filter by a single user (optional)
 *   - page (1-based, default 1)
 *   - pageSize (default 200, max 2000)
 *   - format=csv to download as CSV
 *
 * Examples:
 *   /api/admin/userAllergen
 *   /api/admin/userAllergen?page=1&pageSize=500
 *   /api/admin/userAllergen?userID=798651082169
 *   /api/admin/userAllergen?format=csv
 */
router.get('/userAllergen', async (req, res) => {
  try {
    // Basic params
    const userID = (req.query.userID ?? '').toString().trim();
    const page = Math.max(parseInt(req.query.page ?? '1', 10), 1);
    const pageSize = Math.min(Math.max(parseInt(req.query.pageSize ?? '200', 10), 1), 2000);
    const offset = (page - 1) * pageSize;
    const wantCsv = (req.query.format ?? '').toString().toLowerCase() === 'csv';

    // Build WHERE + SQL parts safely
    const whereParts = [];
    const whereParams = [];
    if (userID) {
      whereParts.push('userID = ?');
      whereParams.push(String(userID));
    }
    const whereSql = whereParts.length ? ('WHERE ' + whereParts.join(' AND ')) : '';

    // Fetch page
    const listSql = `
      SELECT userID, allergenID
      FROM userAllergen
      ${whereSql}
      ORDER BY userID ASC, allergenID ASC
      LIMIT ${pageSize} OFFSET ${offset}
    `;
    const [rows] = await pool.query(listSql, whereParams);

    // Count for total
    const [countRows] = await pool.query(
      `SELECT COUNT(*) AS total FROM userAllergen ${whereSql}`,
      whereParams
    );
    const total = Number(countRows?.[0]?.total ?? 0);

    if (wantCsv) {
      const csv = stringifyCsv(rows);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="userAllergen.csv"');
      return res.status(200).send(csv);
    }

    return res.json({ page, pageSize, total, rows });
  } catch (err) {
    console.error('GET /api/admin/userAllergen error:', err?.message);
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * GET /api/admin/userAllergen/all
 * Streams the entire table without paging (for small datasets).
 * Use carefully if the table is large. Supports optional ?format=csv.
 */
router.get('/userAllergen/all', async (req, res) => {
  try {
    const wantCsv = (req.query.format ?? '').toString().toLowerCase() === 'csv';
    const [rows] = await pool.query(
      `SELECT userID, allergenID
       FROM userAllergen
       ORDER BY userID ASC, allergenID ASC`
    );
    if (wantCsv) {
      const csv = stringifyCsv(rows);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="userAllergen_all.csv"');
      return res.status(200).send(csv);
    }
    return res.json({ total: rows.length, rows });
  } catch (err) {
    console.error('GET /api/admin/userAllergen/all error:', err?.message);
    return res.status(500).json({ error: 'server_error' });
  }
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

/**
 * GET /api/admin/salaryHist
 * Fetches EVERY record available in the salaryHist table without pagination.
 */
router.get('/salaryHist', async (req, res) => {
  try {
    // Query for every record in the table, ordered by the most recent change
    const [rows] = await pool.query(
      `SELECT userID, salary, targetSaving, changedAt
       FROM salaryHist
       ORDER BY changedAt DESC`
    );

    // Return the full array and the total count
    return res.json({
      total: rows.length,
      rows
    });
  } catch (err) {
    console.error('GET /api/admin/salaryHist error:', err?.message);
    return res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;
