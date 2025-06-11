
const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.json());

const statuses = {}; // In-memory store

// Endpoint to store status (used by Zapier)
app.post('/store-status', (req, res) => {
  const { transaction_id, status } = req.body;
  if (!transaction_id || !status) {
    return res.status(400).send('Missing transaction_id or status');
  }
  statuses[transaction_id] = status;
  res.send({ success: true });
});

// Endpoint to check status (polled by the frontend)
app.get('/check-status', (req, res) => {
  const { transaction_id } = req.query;
  if (!transaction_id) {
    return res.status(400).send('Missing transaction_id');
  }
  const status = statuses[transaction_id] || 'pending';
  res.send({ transaction_id, status });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
