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
// Last 10 digits helper (used by phone lookups)
const last10 = (v) => String(v || '').replace(/\D/g, '').slice(-10);

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
    if (acPhone && in
