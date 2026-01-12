
// server.js
const express = require('express');
const app = express();

// 1) Parse JSON request bodies (required for req.body)
app.use(express.json({ limit: '1mb' }));

// 2) Mount your router from routes/index.js
app.use('/', require('./routes/index'));

// 3) Listen on Railway-assigned port
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
