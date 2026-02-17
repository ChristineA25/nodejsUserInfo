
// routes/user.js
const express = require('express');
const axios = require('axios'); // npm i axios (if not present)
const router = express.Router();
const db = require('../db'); // adjust to your project

const DATA_API_BASE = process.env.DATA_API_BASE;

// GET /api/user/blacklist?userID=...   (you already have something like this)
router.get('/blacklist', async (req, res) => {
  try {
    const userID = String(req.query.userID || '');
    if (!userID) return res.status(400).json({ message: 'userID required' });

    const [rows] = await db.query(
      'SELECT itemID FROM userBlacklist WHERE userID = ?',
      [userID]
    );
    const items = rows.map(r => String(r.itemID));
    return res.json({ items });
  } catch (err) {
    console.error('GET /user/blacklist', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/user/blacklist/items?userID=...  -> proxy join (optional)
router.get('/blacklist/items', async (req, res) => {
  try {
    const userID = String(req.query.userID || '');
    if (!userID) return res.status(400).json({ message: 'userID required' });

    // 1) get ids from userBlacklist
    const [rows] = await db.query(
      'SELECT itemID FROM userBlacklist WHERE userID = ?',
      [userID]
    );
    const ids = rows.map(r => String(r.itemID));
    if (!ids.length) return res.json({ items: [] });

    // 2) call data service in bulk
    const { data } = await axios.post(`${DATA_API_BASE}/api/items/byIds`, { ids }, {
      timeout: 8000,
      headers: { 'Content-Type': 'application/json' },
    });

    // Pass-through shape: { items: [...] }
    return res.json({ items: Array.isArray(data.items) ? data.items : [] });
  } catch (err) {
    console.error('GET /user/blacklist/items', err?.response?.status, err?.message);
    res.status(502).json({ message: 'Upstream error' });
  }
});

module.exports = router;
