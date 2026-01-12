
// routes/index.js
const express = require('express');
const router = express.Router();

console.log('✅ routes/index.js loaded');

router.get('/', (req, res) => {
  // If you prefer JSON here, change to res.json({ msg: 'Hello from Railway!' });
  res.send('Hello from Railway route!');
});

router.get('/health', (req, res) => {
  // App-level /health exists for infra; this is fine for app-level checks.
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

module.exports = router;
