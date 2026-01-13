
// routes/index.js
const express = require('express');
const router = express.Router();

console.log('✅ routes/index.js loaded');

router.get('/', (req, res) => {
  res.send('Hello from Railway!');
});

router.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

// Later: router.post('/api/signup', ...)

module.exports = router;
