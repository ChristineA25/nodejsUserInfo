
// server.js
if (process.env.NODE_ENV !== 'production') {
  try {
    require('dotenv').config();
  } catch (e) {
    console.warn('dotenv not loaded (dev only):', e.message);
  }
}

const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Mount your routes
const routes = require('./routes/index');
app.use('/', routes);

// Basic health and root (in case routes fail)
app.get('/healthz', (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// IMPORTANT: Listen on Railway-provided PORT
const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`API listening on port ${port}`);
});
``
