
// app.js
const express = require('express');
const path = require('path');
const indexRouter = require('./routes/index');

const app = express();

// Serve static files from "public"
app.use(express.static(path.join(__dirname, 'public')));

// Attach routes
app.use('/', indexRouter);

// 404 catch-all (must be after routes)
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'views', '404.html'));
});

// Single listener — Railway sets PORT for you
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
});
