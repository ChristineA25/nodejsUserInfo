
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
