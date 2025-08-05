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

// 🔒 Secure endpoint to receive transaction status
app.post('/store-status', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const authorizedKey = process.env.API_KEY;

  if (!apiKey || apiKey !== authorizedKey) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  const { transaction_id, status, email, available_credit, phone } = req.body;

  if (!transaction_id || !status) {
    return res.status(400).json({ success: false, message: 'Missing transaction_id or status' });
  }

  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] Incoming POST /store-status: ${JSON.stringify(req.body)}\n`;
  console.log(logEntry);
  fs.appendFileSync(logFilePath, logEntry);

  statuses[transaction_id] = status;

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

// 🌐 Public endpoint to check status by transaction_id
app.get('/check-status', (req, res) => {
  const { transaction_id } = req.query;

  if (!transaction_id) {
    return res.status(400).json({ success: false, message: 'Missing transaction_id' });
  }

  const status = statuses[transaction_id] || 'pending';
  res.json({ transaction_id, status });
});

// 🆕 Public endpoint to check latest entry by phone number
app.get('/check-latest', (req, res) => {
  const { phone } = req.query;
  if (!phone) {
    return res.status(400).json({ success: false, message: 'Missing phone number' });
  }

  if (!fs.existsSync(logFilePath)) {
    return res.status(404).json({ success: false, message: 'No log file found' });
  }

  const lines = fs.readFileSync(logFilePath, 'utf-8')
    .split('\n')
    .filter(line => line.includes('/store-status:') && line.includes(phone));

  if (lines.length === 0) {
    return res.status(404).json({ success: false, message: 'No entries found for this phone number' });
  }

  // Get the last (most recent) matching log entry
  const lastLine = lines[lines.length - 1];
  const jsonMatch = lastLine.match(/{.*}/);

  if (!jsonMatch) {
    return res.status(500).json({ success: false, message: 'Failed to parse log entry' });
  }

  try {
    const entry = JSON.parse(jsonMatch[0]);
    return res.json({
      available_credit: entry.available_credit,
      transaction_id: entry.transaction_id,
      timestamp: lastLine.substring(1, 20), // Extract timestamp from [..]
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Error parsing JSON log entry' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
