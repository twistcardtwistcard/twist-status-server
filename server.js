require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const statuses = {}; // In-memory transaction store
const logFilePath = path.join(__dirname, 'webhook_logs.txt');

// Secure endpoint to receive transaction status from external webhook
app.post('/store-status', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const authorizedKey = process.env.API_KEY;

  if (!apiKey || apiKey !== authorizedKey) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  const { transaction_id, status, email, available_credit } = req.body;

  if (!transaction_id || !status) {
    return res.status(400).json({ success: false, message: 'Missing transaction_id or status' });
  }

  // Log the full payload with timestamp to console and file
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] Incoming POST /store-status: ${JSON.stringify(req.body)}\n`;
  console.log(logEntry);
  fs.appendFileSync(logFilePath, logEntry);

  statuses[transaction_id] = status;

  // Sync available_credit to ActiveCampaign if email and available_credit are present
  if (email && typeof available_credit !== 'undefined') {
    try {
      const acResponse = await fetch(`${process.env.AC_API_URL}/api/3/contact/sync`, {
        method: 'POST',
        headers: {
          'Api-Token': process.env.AC_API_KEY,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          contact: {
            email: email,
            fieldValues: [
              {
                field: process.env.AC_FIELD_ID,
                value: available_credit
              }
            ]
          }
        })
      });

      const result = await acResponse.json();
      console.log('ActiveCampaign sync response:', result);
    } catch (error) {
      console.error('Error updating ActiveCampaign:', error);
    }
  }

  res.json({ success: true });
});

// Public endpoint to check status (used by frontend)
app.get('/check-status', (req, res) => {
  const { transaction_id } = req.query;

  if (!transaction_id) {
    return res.status(400).json({ success: false, message: 'Missing transaction_id' });
  }

  const status = statuses[transaction_id] || 'pending';
  res.json({ transaction_id, status });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
