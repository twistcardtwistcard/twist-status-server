require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const statuses = {}; // In-memory transaction store

// ✅ Secure endpoint to receive transaction status from external webhook
app.post('/store-status', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const authorizedKey = process.env.API_KEY;

  if (!apiKey || apiKey !== authorizedKey) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  const { transaction_id, status } = req.body;

  if (!transaction_id || !status) {
    return res.status(400).json({ success: false, message: 'Missing transaction_id or status' });
  }

  statuses[transaction_id] = status;
  res.json({ success: true });
});

// 🔍 Public endpoint to check status (used by frontend)
app.get('/check-status', (req, res) => {
  const { transaction_id } = req.query;

  if (!transaction_id) {
    return res.status(400).json({ success: false, message: 'Missing transaction_id' });
  }

  const status = statuses[transaction_id] || 'pending';
  res.json({ transaction_id, status });
});

// 🚀 Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
