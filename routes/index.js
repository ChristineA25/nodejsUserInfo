
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

// Add your /api/signup handler here later (we prepared one previously)

module.exports = router;
