require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

/* ---------------- Static files & hosted form (NO API KEY) ---------------- */
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use('/public', express.static(PUBLIC_DIR));
app.get('/twistpay-form', (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'twistpay-form.html'));
});
// Health check
app.get('/healthz', (_req, res) => res.json({ ok: true }));

/* ---------------- GET protection (allowlist public/form/healthz) ---------------- */
const OPEN_GET_PREFIXES = ['/public', '/twistpay-form', '/healthz'];
app.use((req, res, next) => {
  if (req.method === 'GET' && !OPEN_GET_PREFIXES.some(p => req.path.startsWith(p))) {
    const apiKey = req.headers['x-api-key'];
    const authorizedKey = process.env.GET_API_KEY;
    if (!apiKey || apiKey !== authorizedKey) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
  }
  next();
});

/* ---------------- In-memory status + paths ---------------- */
const statuses = {}; // { transaction_id: 'pending'|'approved'|... }
const logFilePath = path.join(__dirname, 'webhook_logs.txt');
const twistCodePath = path.join('/mnt/data', 'code.json');

/* ---------------- Helpers ---------------- */
function getOrGenerateTwistCode(loanId, expiration) {
  if (!loanId || !expiration) return null;
  const hash = crypto.createHash('sha256').update(`${loanId}|${expiration}`).digest('hex');
  let data = {};
  if (fs.existsSync(twistCodePath)) {
    try { data = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8')); }
    catch { console.error('Failed to parse code.json'); }
  }
  if (data[hash]) return data[hash];
  const newCode = Array.from({ length: 12 }, () => Math.floor(Math.random() * 10)).join('');
  data[hash] = newCode;
  fs.writeFileSync(twistCodePath, JSON.stringify(data, null, 2));
  return newCode;
}
function middle4Of(code12) {
  if (!code12 || String(code12).length < 12) return null;
  return String(code12).slice(4, 8); // digits 5–8
}
function parseMMYY(mmYY) {
  const m = String(mmYY || '').match(/^(\d{2})\/(\d{2})$/);
  return m ? { mm: m[1], yy: m[2] } : null;
}
function normalizeMMYYFromStored(v) {
  if (!v) return null;
  const s = String(v);
  let m;
  if ((m = s.match(/^(\d{2})\/(\d{2})$/))) return `${m[1]}/${m[2]}`;                 // MM/YY
  if ((m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/))) return `${m[2]}/${m[1].slice(-2)}`; // YYYY-MM-DD -> MM/YY
  return null;
}
async function readLatestPayloadByLoanIdEndsWith(last6) {
  try {
    if (!fs.existsSync(logFilePath)) return null;
    const raw = await fsPromises.readFile(logFilePath, 'utf8');
    const lines = raw.split('\n').filter(Boolean).reverse();
    for (const line of lines) {
      if (!line.includes('/store-status:')) continue;
      const jsonMatch = line.match(/{.*}/);
      if (!jsonMatch) continue;
      try {
        const obj = JSON.parse(jsonMatch[0]);
        const loanId = String(obj.loan_id || '');
        if (loanId.endsWith(last6)) return obj;
      } catch {}
    }
  } catch {}
  return null;
}
// Normalize Canadian numbers to E.164 (+1##########)
function normE164CA(v) {
  const digits = String(v || '').replace(/\D/g, '');
  const last10 = digits.slice(-10);
  return last10.length === 10 ? `+1${last10}` : null;
}

/* ---------------- PRE-VALIDATE (rules + OTP) ---------------- */
app.post('/pre-validate', async (req, res) => {
  try {
    const {
      transaction_id,
      orderno,
      amount,
      cardNumber,
      expiration,
      twist,
      email,
      phone,
      postal,
      firstName, lastName, address, city, // captured (no validation here)
      otpCode
    } = req.body || {};

    // Presence
    if (!transaction_id || !orderno || !amount || !cardNumber || !expiration || !twist || !email || !phone || !postal || !otpCode) {
      return res.status(400).json({ ok: false, message: 'Missing required fields.' });
    }

    // Card checks
    const cleanCard = String(cardNumber).replace(/\D/g, '');
    if (!cleanCard.startsWith('71461567')) return res.json({ ok: false, message: 'Card prefix invalid.' });
    if (cleanCard.length !== 16) return res.json({ ok: false, message: 'Card length invalid.' });

    // Map last 6 -> latest payload for that loan
    const last6 = cleanCard.slice(-6);
    const latest = await readLatestPayloadByLoanIdEndsWith(last6);
    if (!latest) return res.json({ ok: false, message: 'No matching loan found.' });

    const loanId = String(latest.loan_id || '');
    const acEmail = String(latest.email || latest.customer_email || '').trim().toLowerCase();
    const acPhone = String(latest.phone || latest.customer_phone || '').replace(/[^\d]/g, '');
    const acPostal = String(latest.postal_code || latest.postal || '').trim().toUpperCase();
    const acAvail = Number(latest.available_credit || 0);
    const acExpiryRaw = String(latest.contract_expiration || ''); // may be MM/YY or YYYY-MM-DD

    // Email
    if (acEmail && String(email).trim().toLowerCase() !== acEmail) {
      return res.json({ ok: false, message: 'Email does not match account.' });
    }

    // Phone (last 10)
    const inPhoneDigits = String(phone).replace(/[^\d]/g, '');
    if (acPhone && inPhoneDigits.slice(-10) !== acPhone.slice(-10)) {
      return res.json({ ok: false, message: 'Phone does not match account.' });
    }

    // Postal
    const inPostal = String(postal).trim().toUpperCase().replace(/\s/g, '');
    const refPostal = acPostal.replace(/\s/g, '');
    if (acPostal && inPostal !== refPostal) {
      return res.json({ ok: false, message: 'Postal code does not match account.' });
    }

    // Amount <= available_credit
    const amt = Number(String(amount).replace(/[^\d.]/g, ''));
    if (Number.isFinite(acAvail) && Number.isFinite(amt) && amt > acAvail) {
      return res.json({ ok: false, message: 'Amount exceeds available credit.' });
    }

    // Expiration match
    const inExp = parseMMYY(expiration);
    if (!inExp) return res.json({ ok: false, message: 'Expiration format invalid.' });
    const storedMMYY = normalizeMMYYFromStored(acExpiryRaw);
    if (!storedMMYY || storedMMYY !== `${inExp.mm}/${inExp.yy}`) {
      return res.json({ ok: false, message: 'Expiration does not match contract.' });
    }

    // TWIST middle 4 (code.json uses hash(loan_id|contract_expiration))
    let twistMap = {};
    if (fs.existsSync(twistCodePath)) {
      try { twistMap = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8')); } catch {}
    }
    const hashKey = crypto.createHash('sha256').update(`${loanId}|${acExpiryRaw}`).digest('hex');
    const fullCode = twistMap[hashKey];
    const mid4 = middle4Of(fullCode);
    if (!mid4 || String(twist) !== mid4) {
      return res.json({ ok: false, message: 'TWIST code incorrect.' });
    }

    // OTP verification (server-side) with normalized phone
    const normPhone = normE164CA(phone);
    if (!normPhone) return res.json({ ok: false, message: 'Phone format invalid.' });
    const otpResp = await fetch('https://twilio-otp-server.onrender.com/verify-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: normPhone, code: otpCode })
    });
    const otpData = await otpResp.json().catch(() => null);
    if (!otpData || !otpData.success) {
      return res.json({ ok: false, message: 'OTP invalid or expired.' });
    }

    // Mark as pending so client polling works without exposing GET key
    statuses[transaction_id] = 'pending';

    return res.json({ ok: true, message: 'Validated', loan_id: loanId });
  } catch (e) {
    console.error('pre-validate error:', e);
    return res.status(500).json({ ok: false, message: 'Server error' });
  }
});

/* ---------------- Secure status store (from your processor) ---------------- */
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
    code,
    product_description // optional
  } = req.body;

  if (!transaction_id || !status) {
    return res.status(400).json({ success: false, message: 'Missing transaction_id or status' });
  }

  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] Incoming POST /store-status: ${JSON.stringify(req.body)}\n`;
  console.log(logEntry);
  fs.appendFileSync(logFilePath, logEntry);

  statuses[transaction_id] = status;

  // Optional: sync to ActiveCampaign
  if (email) {
    const fieldValues = [];
    if (typeof available_credit !== 'undefined') fieldValues.push({ field: 78, value: available_credit });
    if (typeof loan_id !== 'undefined') fieldValues.push({ field: 80, value: loan_id });
    if (typeof contract_expiration !== 'undefined') fieldValues.push({ field: 86, value: contract_expiration });
    if (typeof product_code !== 'undefined') fieldValues.push({ field: 84, value: product_code });
    if (typeof state !== 'undefined') fieldValues.push({ field: 85, value: state });
    if (typeof limit !== 'undefined') fieldValues.push({ field: 82, value: limit });
    if (typeof product_description !== 'undefined') fieldValues.push({ field: 88, value: product_description });
    if (state === 'active') fieldValues.push({ field: 79, value: 'YES' });
    try {
      await fetch(`${process.env.AC_API_URL}/api/3/contact/sync`, {
        method: 'POST',
        headers: { 'Api-Token': process.env.AC_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ contact: { email, fieldValues } })
      });
    } catch (err) {
      console.error('ActiveCampaign update error:', err);
    }
  }

  // Ensure a twistcode exists
  if (loan_id && contract_expiration) {
    getOrGenerateTwistCode(loan_id, contract_expiration);
  }

  res.json({ success: true });
});

/* ---------------- Safe client polling (no API key) ---------------- */
app.post('/client-check-status', (req, res) => {
  try {
    const { transaction_id } = req.body || {};
    if (!transaction_id) return res.status(400).json({ success: false, message: 'Missing transaction_id' });
    const status = statuses[transaction_id] || 'pending';
    return res.json({ success: true, status });
  } catch (e) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ---------------- Existing GET routes (still protected) ---------------- */
app.get('/check-status', (req, res) => {
  const { transaction_id } = req.query;
  if (!transaction_id) return res.status(400).json({ success: false, message: 'Missing transaction_id' });
  const status = statuses[transaction_id] || 'pending';
  res.json({ transaction_id, status });
});

app.get('/check-latest', (req, res) => {
  const { phone } = req.query;
  if (!phone) return res.status(400).json({ success: false, message: 'Missing phone number' });
  if (!fs.existsSync(logFilePath)) return res.status(404).json({ success: false, message: 'No log file found' });

  const lines = fs.readFileSync(logFilePath, 'utf-8')
    .split('\n')
    .filter(line => line.includes('/store-status:') && line.includes(phone));

  if (lines.length === 0) return res.status(404).json({ success: false, message: 'No entries found for this phone number' });

  const lastLine = lines[lines.length - 1];
  const jsonMatch = lastLine.match(/{.*}/);
  if (!jsonMatch) return res.status(500).json({ success: false, message: 'Failed to parse log entry' });

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

/* ---------------- Boot ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
