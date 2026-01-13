
// app.js
const express = require('express');
const path = require('path');

const app = express();

/**
 * Simple health endpoint for Railway.
 * Always returns 200 when the process is up.
 * Configure Railway Healthcheck to hit /health (GET).
 */
app.get('/health', (req, res) => {
  res.status(200).send('ok');
});

// Serve static files from "public"
app.use(express.static(path.join(__dirname, 'public')));

// Try to attach the index router (logs if it fails)
let indexRouterMounted = false;
try {
  const indexRouter = require('./routes/index'); // requires routes/index.js (case-sensitive)
  app.use('/', indexRouter);
  indexRouterMounted = true;
  console.log('✅ indexRouter mounted');
} catch (err) {
  console.error('❌ Failed to load ./routes/index:', err);
}

// 404 catch-all (must be after routes and static)
app.use((req, res) => {
  // If you have views/404.html, this will serve it; otherwise send plain text.
  const fallback404 = path.join(__dirname, 'views', '404.html');
  res.status(404).sendFile(fallback404, (sendErr) => {
    if (sendErr) {
      res
        .status(404)
        .type('text')
        .send('404 – Not Found');
    }
  });
});

// Single listener — Railway sets PORT for you
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
  if (!indexRouterMounted) {
    console.warn('⚠️ indexRouter was not mounted. Only static files and /health are active.');
  }
});


// Example only (CommonJS); adapt to your project structure & error handling
app.post('/signup', async (req, res) => {
  const {
    username, password, email,
    phone_country_code, phone_number,
    secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3
  } = req.body;

  if (!password) return res.status(400).json({ error: 'password is required' });

  // TODO: hash the password (e.g., bcrypt.hash(password, 12))
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

  try {
    const [result] = await pool.execute(sql, params);
    return res.status(201).json({ userID: result.insertId });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});
