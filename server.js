require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Middleware to protect all GET routes with GET_API_KEY
app.use((req, res, next) => {
  if (req.method === 'GET') {
    const apiKey = req.headers['x-api-key'];
    const authorizedKey = process.env.GET_API_KEY;
    if (!apiKey || apiKey !== authorizedKey) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
  }
  next();
});

const statuses = {}; // In-memory transaction store
const logFilePath = path.join(__dirname, 'webhook_logs.txt');
const twistCodePath = path.join(__dirname, 'code.json');

function getOrGenerateTwistCode(loanId, expiration) {
  if (!loanId || !expiration) return null;
  const hash = crypto.createHash('sha256').update(`${loanId}|${expiration}`).digest('hex');
  let data = {};

  if (fs.existsSync(twistCodePath)) {
    try {
      data = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8'));
    } catch (e) {
      console.error('Failed to parse code.json');
    }
  }

  if (data[hash]) return data[hash];

  const newCode = Array.from({ length: 12 }, () => Math.floor(Math.random() * 10)).join('');
  data[hash] = newCode;

  console.log('🔧 Writing twistcode to:', twistCodePath);
  console.log('📦 Data to write:', JSON.stringify(data, null, 2));

  fs.writeFileSync(twistCodePath, JSON.stringify(data, null, 2));
  console.log(`Generated new twistcode: ${newCode} for hash: ${hash}`);
  return newCode;
}

// 🔒 Enregistrement sécurisé d’un statut
app.post('/store-status', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const authorizedKey = process.env.API_KEY;

  if (!apiKey || apiKey !== authorizedKey) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  const {
    transaction_id,
    status,
    email,
    available_credit,
    loan_id,
    contract_expiration,
    product_code,
    state,
    limit,
    phone,
    code
  } = req.body;

  if (!transaction_id || !status) {
    return res.status(400).json({ success: false, message: 'Missing transaction_id or status' });
  }

  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] Incoming POST /store-status: ${JSON.stringify(req.body)}\n`;
  console.log(logEntry);
  fs.appendFileSync(logFilePath, logEntry);

  statuses[transaction_id] = status;

  // 🔁 Sync to ActiveCampaign if email is present
  if (email) {
    const fieldValues = [];
    if (typeof available_credit !== 'undefined') fieldValues.push({ field: 78, value: available_credit });
    if (typeof loan_id !== 'undefined') fieldValues.push({ field: 80, value: loan_id });
    if (typeof contract_expiration !== 'undefined') fieldValues.push({ field: 86, value: contract_expiration });
    if (typeof product_code !== 'undefined') fieldValues.push({ field: 84, value: product_code });
    if (typeof state !== 'undefined') fieldValues.push({ field: 85, value: state });
    if (typeof limit !== 'undefined') fieldValues.push({ field: 82, value: limit });

    if (state === 'active') fieldValues.push({ field: 79, value: 'YES' });

    try {
      await fetch(`${process.env.AC_API_URL}/api/3/contact/sync`, {
        method: 'POST',
        headers: {
          'Api-Token': process.env.AC_API_KEY,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ contact: { email, fieldValues } })
      });
    } catch (err) {
      console.error('ActiveCampaign update error:', err);
    }
  }

  // 🔑 Generate twistcode
  if (loan_id && contract_expiration) {
    getOrGenerateTwistCode(loan_id, contract_expiration);
  }

  res.json({ success: true });
});

// 🔍 Vérification par transaction_id
app.get('/check-status', (req, res) => {
  const { transaction_id } = req.query;
  if (!transaction_id) {
    return res.status(400).json({ success: false, message: 'Missing transaction_id' });
  }
  const status = statuses[transaction_id] || 'pending';
  res.json({ transaction_id, status });
});

// 🆕 Vérification du dernier enregistrement par numéro (sans +)
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

  const lastLine = lines[lines.length - 1];
  const jsonMatch = lastLine.match(/{.*}/);
  if (!jsonMatch) {
    return res.status(500).json({ success: false, message: 'Failed to parse log entry' });
  }

  try {
    const entry = JSON.parse(jsonMatch[0]);

    const loanId = entry.loan_id;
    const expiration = entry.contract_expiration;
    let twistcode = null;

    if (loanId && expiration && fs.existsSync(twistCodePath)) {
      const hash = crypto.createHash('sha256').update(`${loanId}|${expiration}`).digest('hex');
      const data = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8'));
      twistcode = data[hash] || null;
    }

    return res.json({
      transaction_id: entry.transaction_id,
      timestamp: lastLine.substring(1, 20),
      code: twistcode
    });

  } catch (err) {
    return res.status(500).json({ success: false, message: 'Error parsing log entry' });
  }
});

// 🆕 Get twistcode by loan_id and contract_expiration
app.get('/get-code', (req, res) => {
  const { loan_id, contract_expiration } = req.query;
  if (!loan_id || !contract_expiration) {
    return res.status(400).json({ success: false, message: 'Missing loan_id or contract_expiration' });
  }

  const hash = crypto.createHash('sha256').update(`${loan_id}|${contract_expiration}`).digest('hex');
  if (!fs.existsSync(twistCodePath)) {
    return res.status(404).json({ success: false, message: 'code.json not found' });
  }

  const data = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8'));
  const twistcode = data[hash];
  if (!twistcode) {
    return res.status(404).json({ success: false, message: 'No twistcode found for this pair' });
  }

  res.json({ twistcode });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
