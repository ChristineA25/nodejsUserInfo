
const express = require('express');
const path = require('path');
const app = express();

// static files (optional)
app.use(express.static(path.join(__dirname, 'public')));

// root route
app.get('/', (req, res) => {
  res.send('Hello from Railway!');
});

// IMPORTANT: use Railway PORT and bind 0.0.0.0
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on ${PORT}`);
});

module.exports = app; // optional if tests or separate server file
