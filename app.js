
// app.js
const express = require('express');
const path = require('path');

const app = express();

// --- Manual CORS (fixed list) ---
const allowedOrigins = new Set([
  'http://localhost:5173',                  // dev origin (adjust)
  'https://your-flutter-web-domain.example' // prod origin (replace)
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Only echo back known origins
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  // Help caches vary by Origin
  res.setHeader('Vary', 'Origin');

  // Methods your API supports
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');

  // Headers your browser may send (add any custom ones here)
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, x-api-key');

  // If this is the CORS preflight, end it early
  if (req.method === 'OPTIONS') {
    // Optionally advertise how long the preflight can be cached
    res.setHeader('Access-Control-Max-Age', '86400'); // 24h
    return res.status(204).end();
  }

  next();
});
// --- End Manual CORS ---

app.use(express.json());

// Example health route
app.get('/health', (_req, res) => res.json({ ok: true }));

// Static, routes, etc.
app.use(express.static(path.join(__dirname, 'public')));

// Listen on Railway-provided PORT
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`Listening on http://0.0.0.0:${PORT}`)
);
