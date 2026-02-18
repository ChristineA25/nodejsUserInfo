
// routes/index.js
const express = require('express');
const mysql = require('mysql2/promise');
const router = express.Router();

console.log('✅ routes/index.js loaded');

// --- DB pool (Railway env) ---------------------------------------------------
const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: Number(process.env.MYSQLPORT || 3306),
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0,
});

router.get('/', (req, res) => res.send('Hello from Railway!'));
router.get('/health', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 AS ok');
    res.json({ status: rows[0]?.ok === 1 ? 'ok' : 'bad', ts: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ status: 'bad', error: e.message });
  }
});

// --- USER BLACKLIST ----------------------------------------------------------
// GET /api/user/blacklist?userID=123
router.get('/api/user/blacklist', async (req, res) => {
  try {
    const userID = String(req.query.userID ?? '').trim();
    if (!userID) return res.status(400).json({ error: 'userID_required' });

    const [rows] = await pool.query(
      'SELECT `itemID` FROM `userBlacklist` WHERE `userID` = ?',
      [userID]
    );
    const items = rows.map(r => String(r.itemID ?? '')).filter(Boolean);
    return res.json({ items });
  } catch (e) {
    console.error('GET /api/user/blacklist error:', e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// PUT /api/user/blacklist  { userID: "...", items: ["id1","id2", ...] }
router.put('/api/user/blacklist', async (req, res) => {
  const userID = String(req.body?.userID ?? '').trim();
  const items = Array.isArray(req.body?.items) ? req.body.items.filter(Boolean) : [];
  if (!userID) return res.status(400).json({ error: 'userID_required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('DELETE FROM `userBlacklist` WHERE `userID` = ?', [userID]);

    if (items.length) {
      const values = items.map(id => [id, userID]); // (itemID, userID)
      await conn.query('INSERT INTO `userBlacklist` (`itemID`,`userID`) VALUES ?', [values]);
    }

    await conn.commit();
    return res.json({ ok: true, count: items.length });
  } catch (e) {
    await conn.rollback();
    console.error('PUT /api/user/blacklist error:', e);
    return res.status(500).json({ error: 'server_error' });
  } finally {
    conn.release();
  }
});

module.exports = router;
