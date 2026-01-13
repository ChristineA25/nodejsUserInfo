
// app.js
const express = require('express');
const path = require('path');

// TODO: make sure you actually create and export a MySQL pool somewhere.
// Example (adjust to your Railway MySQL credentials):
// const mysql = require('mysql2/promise');
// const pool = mysql.createPool({
//   host: process.env.MYSQLHOST,
//   user: process.env.MYSQLUSER,
//   password: process.env.MYSQLPASSWORD,
//   database: process.env.MYSQLDATABASE,
//   port: process.env.MYSQLPORT || 3306,
//   waitForConnections: true,
//   connectionLimit: 10,
//   queueLimit: 0,
// });
const { pool } = require('./db'); // or replace with inline creation above

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
// Use the path that Flutter expects:
app.post('/api/signup', async (req, res) => {
  try {
    const {
      username, password, email,
      phone_country_code, phone_number,
      secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3
    } = req.body || {};

    if (!password) {
      return res.status(400).json({ error: 'password_required' });
    }

    // TODO: hash the password (bcrypt/argon2)
    // const hashed = await bcrypt.hash(password, 12);
    const hashed = password; // replace with real hash

    const sql = `
      INSERT INTO loginTable
        (username, password, email, phone_country_code, phone_number,
         secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
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
    return res.status(201).json({ userID: result.insertId });
  } catch (err) {
    // Map some common MySQL errors to friendlier codes
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
