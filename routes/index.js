
// routes/index.js (ES Modules Router)
import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';

const router = express.Router();
router.use(cors());
router.use(express.json({ limit: '256kb' }));

// Optional: simple API key gate (set API_KEY in Railway vars)
const API_KEY = process.env.API_KEY;
router.use((req, res, next) => {
  if (!API_KEY) return next();                 // allow all if not configured
  const key = req.get('x-api-key');
  if (key !== API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
});

console.log('DB VARS SNAPSHOT', {
  MYSQLHOST: process.env.MYSQLHOST,
  MYSQLUSER: process.env.MYSQLUSER,
  MYSQLDATABASE: process.env.MYSQLDATABASE,  // should NOT be undefined/empty
  MYSQLPORT: process.env.MYSQLPORT,
});

// ---- MySQL pool (Railway) ---------------------------------------------------
const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: Number(process.env.MYSQLPORT || 3306),
  ssl: { rejectUnauthorized: false }, // typical for Railway
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000
});

// ---- Helpers ----------------------------------------------------------------
/** Normalize to canonical '+<digits>' (e.g., '+ 1-264' -> '+1264') */
function normalizeCode(s) {
  const raw = String(s || '');
  const digits = raw.replace(/[^\d+]/g, '');   // keep '+' and digits
  if (!digits.startsWith('+')) {
    return '+' + digits.replace(/\D/g, '');
  }
  return '+' + digits.slice(1).replace(/\D/g, '');
}

// ---- Routes: root & health --------------------------------------------------
router.get('/', (_req, res) => res.send('API is running'));
router.get('/health', async (_req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 AS ok');
    return res.json({ ok: rows[0]?.ok === 1 });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// --- ITEMS: search the `item` table (fetch-only) -----------------------------
router.get('/api/items/search', async (req, res) => {
  try {
    const q = String(req.query.q ?? '').trim();
    const field = String(req.query.field ?? 'all').toLowerCase();
    const limit = Math.min(parseInt(String(req.query.limit ?? '50'), 10) || 50, 100);

    const allow = new Set(['all','name','brand','quantity','feature','productcolor']);
    if (!allow.has(field)) return res.status(400).json({ error: 'invalid_field' });

    const where = [];
    const params = [];

    if (q) {
      const like = `%${q}%`;
      if (field === 'all') {
        where.push(`(name LIKE ? OR brand LIKE ? OR quantity LIKE ? OR feature LIKE ? OR productColor LIKE ?)`);
        params.push(like, like, like, like, like);
      } else if (field === 'productcolor') {
        where.push(`productColor LIKE ?`);
        params.push(like);
      } else {
        where.push(`${field} LIKE ?`);
        params.push(like);
      }
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const sql = `
      SELECT id, name, brand, quantity, feature, productColor, picWebsite
      FROM item
      ${whereSql}
      ORDER BY name ASC, brand ASC
      LIMIT ?
    `;
    params.push(limit);

    const [rows] = await pool.query(sql, params);
    const items = rows.map(r => ({
      id: String(r.id ?? ''),
      name: String(r.name ?? ''),
      brand: String(r.brand ?? ''),
      quantity: String(r.quantity ?? ''),
      feature: String(r.feature ?? ''),
      productColor: String(r.productColor ?? ''),
      picWebsite: String(r.picWebsite ?? ''),
    }));
    return res.json({ items });
  } catch (e) {
    console.error('Error in /api/items/search:', e);
    return res.status(500).json({ error: 'items_search_failed' });
  }
});

// ---- PHONE: regions from MySQL ---------------------------------------------
router.get('/phone/regions', async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        regionName              AS name,
        regionPhoneCode         AS phoneCode,
        minRegionPhoneLength    AS minLen,
        maxRegionPhoneLength    AS maxLen,
        countryFlag             AS iso2
      FROM phoneInfo
      WHERE countryFlag IS NOT NULL AND countryFlag <> ''
      ORDER BY name ASC
    `);

    const regions = rows.map(r => {
      const iso2 = String(r.iso2 || '').trim().toUpperCase();
      const displayCode = String(r.phoneCode ?? '').trim();
      const code = normalizeCode(displayCode);
      return {
        iso2,
        name: String(r.name || '').trim(),
        code,            // e.g. '+44'
        displayCode,     // e.g. '+ 1-264'
        min: Number(r.minLen || 0),
        max: Number(r.maxLen || 0),
      };
    });

    return res.json({ regions });
  } catch (e) {
    console.error('Error in /phone/regions:', e);
    return res.status(500).json({ error: 'Failed to load regions' });
  }
});

// --- ALLERGENS ---------------------------------------------------------------
router.get('/api/allergens', async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT DISTINCT allergenCommonName AS name
         FROM commonAllergen
        WHERE allergenCommonName IS NOT NULL
          AND allergenCommonName <> ''
        ORDER BY allergenCommonName ASC`
    );
    const items = rows.map(r => (r.name ?? '').toString().trim()).filter(Boolean);
    res.json({ items });
  } catch (e) {
    console.error('Error in /api/allergens:', e);
    res.status(500).json({ error: 'allergens_fetch_failed' });
  }
});

// --- Location lookups --------------------------------------------------------
router.get('/api/counties', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT DISTINCT county FROM gbrPostcodeNameSake WHERE county IS NOT NULL AND county <> '' ORDER BY county ASC`
    );
    res.json({ items: rows.map(r => r.county) });
  } catch (e) {
    res.status(500).json({ error: 'counties_fetch_failed' });
  }
});

router.get('/api/districts', async (req, res) => {
  try {
    const { county } = req.query;
    if (!county) return res.status(400).json({ error: 'county_required' });

    const [rows] = await pool.execute(
      `SELECT DISTINCT district 
         FROM gbrPostcodeNameSake 
        WHERE county = ? AND district IS NOT NULL AND district <> '' 
        ORDER BY district ASC`,
      [county]
    );
    res.json({ items: rows.map(r => r.district) });
  } catch (e) {
    res.status(500).json({ error: 'districts_fetch_failed' });
  }
});

router.get('/api/postcodes', async (req, res) => {
  try {
    const { county, district } = req.query;
    if (!county)   return res.status(400).json({ error: 'county_required' });
    if (!district) return res.status(400).json({ error: 'district_required' });

    const [rows] = await pool.execute(
      `SELECT DISTINCT postcode 
         FROM gbrPostcodeNameSake 
        WHERE county = ? AND district = ? AND postcode IS NOT NULL AND postcode <> '' 
        ORDER BY postcode ASC`,
      [county, district]
    );
    res.json({ items: rows.map(r => r.postcode) });
  } catch (e) {
    res.status(500).json({ error: 'postcodes_fetch_failed' });
  }
});

// --- SHOPS -------------------------------------------------------------------
router.get('/shops', async (_req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT DISTINCT `shopName` AS name FROM `chainShop` ORDER BY `shopName` ASC'
    );
    const shops = rows.map(r => (r.name ?? '').toString().trim()).filter(Boolean);
    res.json({ shops });
  } catch (e) {
    console.error('Error in /shops:', e);
    res.status(500).json({ error: 'Failed to load shops' });
  }
});

// --- BRANDS (NOW FROM `item`) -----------------------------------------------
router.get('/brands', async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT DISTINCT brand AS name
         FROM item
        WHERE brand IS NOT NULL AND brand <> ''
        ORDER BY brand ASC`
    );
    const brands = rows.map(r => (r.name ?? '').toString().trim()).filter(Boolean);
    res.json({ brands });
  } catch (e) {
    console.error('Error in /brands:', e);
    res.status(500).json({ error: 'Failed to load brands' });
  }
});

// --- ITEMS (NOW FROM `item`; brand filter supported) -------------------------
router.get('/items', async (req, res) => {
  try {
    const { brand /* channel, shopID (ignored for backward-compat) */ } = req.query;
    const where = [];
    const params = [];
    if (brand) { where.push('brand = ?'); params.push(brand); }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const sql = `
      SELECT DISTINCT name AS name
      FROM item
      ${whereSql}
      ORDER BY name ASC
    `;
    const [rows] = await pool.query(sql, params);
    const items = rows.map(r => (r.name ?? '').toString().trim()).filter(Boolean);
    res.json({ items });
  } catch (e) {
    console.error('Error in /items:', e);
    res.status(500).json({ error: 'Failed to load items' });
  }
});

// --- TEXTLESS endpoints (left as-is) ----------------------------------------
router.get('/items-textless', async (_req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT DISTINCT `item` AS name FROM `itemColor4` WHERE `item` IS NOT NULL AND `item` <> "" ORDER BY `item` ASC'
    );
    const items = rows.map(r => (r.name ?? '').toString().trim()).filter(Boolean);
    res.json({ items });
  } catch (e) {
    console.error('Error in /items-textless:', e);
    res.status(500).json({ error: 'Failed to load textless items' });
  }
});

router.get('/item-colors-textless', async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT \`item\` AS item, \`color\` AS colors
      FROM \`itemColor4\`
      WHERE \`item\` IS NOT NULL AND \`item\` <> ""
    `);
    const data = rows.map(r => ({
      item: (r.item ?? '').toString().trim(),
      colors: (r.colors ?? '')
        .toString()
        .toLowerCase()
        .split(',')
        .map(s => s.trim())
        .filter(Boolean),
    })).filter(x => x.item.length > 0);
    res.json({ items: data });
  } catch (e) {
    console.error('Error in /item-colors-textless:', e);
    res.status(500).json({ error: 'Failed to load textless item colours' });
  }
});

// --- ITEM COLORS (NOW FROM `item`) -------------------------------------------
router.get('/item-colors', async (req, res) => {
  try {
    const { brand /* channel, shopID ignored */ } = req.query;
    const where = [];
    const params = [];
    if (brand) { where.push('brand = ?'); params.push(brand); }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const [rows] = await pool.query(`
      SELECT name AS item, productColor AS colors
      FROM item
      ${whereSql}
    `, params);

    // Keep the longest colors string per item (matches your previous logic)
    const byItem = new Map();
    for (const r of rows) {
      const item = (r.item ?? '').toString().trim();
      const colorsStr = (r.colors ?? '').toString().trim();
      if (!item || !colorsStr) continue;
      const existing = byItem.get(item) ?? '';
      if (colorsStr.length > existing.length) byItem.set(item, colorsStr);
    }
    const data = Array.from(byItem.entries()).map(([item, colorsStr]) => ({
      item,
      colors: colorsStr
        .toLowerCase()
        .split(',')
        .map(s => s.trim())
        .filter(Boolean),
    })).sort((a, b) => a.item.localeCompare(b.item));

    res.json({ items: data });
  } catch (e) {
    console.error('Error in /item-colors:', e);
    res.status(500).json({ error: 'Failed to load item colours' });
  }
});

// --- Simple test insert (unchanged) ------------------------------------------
router.post('/add', async (req, res) => {
  const { testing } = req.body || {};
  if (!testing) return res.status(400).json({ error: 'Field "testing" is required.' });
  try {
    const [result] = await pool.query('INSERT INTO testing (testing) VALUES (?)', [testing]);
    res.status(201).json({ id: result.insertId, testing });
  } catch (err) {
    console.error('Insert error:', err);
    res.status(500).json({ error: 'Database insert failed.' });
  }
});

export default router;
