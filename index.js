
// routes/index.js
const express = require('express');
const router = express.Router();

// Root route
router.get('/', (req, res) => {
  res.send('Hello from Railway!');
});

// Example healthcheck
router.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

module.exports = router;
