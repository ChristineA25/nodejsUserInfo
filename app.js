
// app.js
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');            // make sure bcryptjs is in dependencies
const { pool } = require('./db');              // db.js must export a mysql2/promise pool

const app = express();

// Parse JSON (needed for req.body)
app.use(express.json());

// Simple health endpoint for Railway
app.get('/health', (req, res) => {
  res.status(200).send('ok');
});

// Serve static files from "public"
app.use(express.static(path.join(__dirname, 'public')));

// Try to attach the index router (optional)
let indexRouterMounted = false;
try {
  const indexRouter = require('./routes/index');
  app.use('/', indexRouter);
  indexRouterMounted = true;
  console.log('✅ indexRouter mounted');
} catch (err) {
  console.error('❌ Failed to load ./routes/index:', err);
}

// --- API routes ---

/**
 * POST /api/signup
 * Expects JSON body including a client-supplied userID (from Flutter).
 * Example body:
 * {
 *   "userID": 2,
 *   "username": "railway_test",
 *   "password": "Passw0rd!123",
 *   "email": "railway@example.com",
 *   "phone_country_code": "+44",
 *   "phone_number": "07123456789",
 *   "secuQuestion1": "First pet?",
 *   "secuAns1": "Milo",
 *   "secuQuestion2": "Birth city?",
 *   "secuAns2": "Hong Kong",
 *   "secuQuestion3": "Favourite colour?",
 *   "secuAns3": "Blue"
 * }
 */
app.post('/api/signup', async (req, res) => {
  try {
    const {
      userID,
      username, password, email,
      phone_country_code, phone_number,
      secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3
    } = req.body || {};

    // Basic validation — adjust as needed
    if (userID === undefined || userID === null || userID === '') {
      return res.status(400).json({ error: 'userID_required' });
    }
    if (!password) {
      return res.status(400).json({ error: 'password_required' });
    }

    // Hash the password (bcryptjs)
    const hashed = await bcrypt.hash(String(password), 12);

    // IMPORTANT: Insert userID explicitly since your MySQL column requires it
    const sql = `
      INSERT INTO loginTable
        (userID, username, password, email, phone_country_code, phone_number,
         secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
      userID,
      username ?? null,
      hashed,
      email ?? null,
      phone_country_code ?? null,
      phone_number ?? null,
      secuQuestion1 ?? null,
      secuAns1 ?? null,
      secuQuestion2 ?? null,
      secuAns2 ?? null,
      secuQuestion3 ?? null,
      secuAns3 ?? null,
    ];

    const [result] = await pool.execute(sql, params);

    // Return the userID provided by client
    return res.status(201).json({ userID });
  } catch (err) {
    const msg = (err && err.message) ? err.message : 'unknown_error';
    const code = (err && err.code) ? err.code : null;

    // Example: ER_DUP_ENTRY for unique constraint violation
    if (code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'duplicate_identifier' });
    }

    return res.status(500).json({ error: msg });
  }
});

// 404 catch-all (after routes and static)
app.use((req, res) => {
  const fallback404 = path.join(__dirname, 'views', '404.html');
  res.status(404).sendFile(fallback404, (sendErr) => {
    if (sendErr) {
      res.status(404).type('text').send('404 – Not Found');
    }
  });
});

// Single listener — Railway sets PORT for you
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
  if (!indexRouterMounted) {
    console.warn('⚠️ indexRouter was not mounted. Only static files and /health + /api/signup are active.');
  }
});
