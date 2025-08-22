require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
/* PATCH: import validator (kept from last good version) */
const { validateTransaction } = require('./validation');
/* NEW: durable payload index module */
const payloadIndex = require('./lib/payloadIndex');

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
const statuses = {}; // { transaction_id: 'pending'|'approved'|'denied' }

/**
 * Robust log handling:
 * - Primary path from env LOG_FILE_PATH or defaults to /mnt/data/webhook_logs.txt (persistent on Render)
 * - Fallback path in app directory ./webhook_logs.txt
 * - Touch primary on boot; write to both when possible.
 * - Reader merges BOTH logs and sorts newest→oldest by timestamp.
 */
const LOG_PRIMARY = process.env.LOG_FILE_PATH || path.join('/mnt/data', 'webhook_logs.txt');
const LOG_FALLBACK = path.join(__dirname, 'webhook_logs.txt');
const twistCodePath = path.join('/mnt/data', 'code.json');

// Ensure primary log exists (touch)
try {
  fs.mkdirSync(path.dirname(LOG_PRIMARY), { recursive: true });
  fs.closeSync(fs.openSync(LOG_PRIMARY, 'a'));
} catch (e) {
  console.error('Unable to touch primary log file:', LOG_PRIMARY, e);
}

/* ---- Log helpers ---- */
function logWrite(line) {
  try { fs.appendFileSync(LOG_PRIMARY, line); } catch (e) { console.error('write primary failed', e); }
  try { fs.appendFileSync(LOG_FALLBACK, line); } catch (_) { /* ignore fallback write errors */ }
}

/**
 * Read and MERGE lines from both logs (if present), sorted newest→oldest.
 * It uses the timestamp between '[' and ']' if present, else preserves relative order.
 */
function readMergedLogText() {
  const files = [];
  try { if (fs.existsSync(LOG_PRIMARY)) files.push(LOG_PRIMARY); } catch {}
  try { if (fs.existsSync(LOG_FALLBACK)) files.push(LOG_FALLBACK); } catch {}
  if (files.length === 0) return null;

  let lines = [];
  for (const p of files) {
    try {
      const raw = fs.readFileSync(p, 'utf-8');
      if (raw && raw.length) lines.push(...raw.trimEnd().split('\n').filter(Boolean));
    } catch {}
  }
  if (!lines.length) return null;

  const withIndex = lines.map((line, idx) => {
    const s = line.indexOf('[');
    const e = line.indexOf(']');
    const ts = (s >= 0 && e > s) ? Date.parse(line.slice(s + 1, e)) : NaN;
    return { line, idx, ts: isNaN(ts) ? null : ts };
  });

  withIndex.sort((a, b) => {
    if (a.ts !== null && b.ts !== null && a.ts !== b.ts) return b.ts - a.ts; // newer first
    return a.idx - b.idx; // stable fallback
  });

  return withIndex.map(x => x.line).join('\n');
}

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
  return String(code12).slice(4, 8);
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

// Convert any supported expiration format to MMYY (digits only)
function toMMYY(raw) {
  const s = String(raw || '').trim();
  let m;
  if (/^\d{4}$/.test(s)) return s;                              // MMYY
  if ((m = s.match(/^(\d{2})\/(\d{2})$/))) return m[1] + m[2];   // MM/YY -> MMYY
  if ((m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/))) return m[2] + m[1].slice(-2); // YYYY-MM-DD -> MMYY
  return null;
}

/* --------- Phone + expiration utilities for resilient matching --------- */
function phonesFromEntry(entry) {
  if (!entry || typeof entry !== 'object') return [];
  const out = [];
  for (const [k, v] of Object.entries(entry)) {
    if (/phone/i.test(k) && typeof v === 'string') out.push(v);
  }
  return out;
}
const last10 = (v) => String(v || '').replace(/\D/g, '').slice(-10);
function expCandidates(v) {
  const s = String(v || '').trim();
  const out = new Set();
  if (s) out.add(s);
  let m = s.match(/^(\d{2})\/(\d{2})$/);
  if (m) { out.add(`${m[1]}${m[2]}`); out.add(`${m[1]}/${m[2]}`); }
  if (/^\d{4}$/.test(s)) { out.add(s); out.add(`${s.slice(0,2)}/${s.slice(2)}`); }
  m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (m) {
    out.add(`${m[2]}${m[1].slice(-2)}`);
    out.add(`${m[2]}/${m[1].slice(-2)}`);
    out.add(s);
  }
  return Array.from(out);
}
function findTwistByLoanAndExpVariants(loanId, expiration, codeMap) {
  if (!loanId || !expiration || !codeMap) return null;
  for (const exp of expCandidates(expiration)) {
    const hash = crypto.createHash('sha256').update(`${loanId}|${exp}`).digest('hex');
    if (codeMap[hash]) return { twistcode: codeMap[hash], usedExpiration: exp };
  }
  return null;
}

/**
 * Scan newest→oldest across MERGED logs.
 * Accept ANY line that contains a JSON object (old logs might not have "/store-status:" marker).
 */
async function readLatestPayloadByLoanIdEndsWith(last6) {
  try {
    const raw = readMergedLogText();
    if (!raw) return null;
    const lines = raw.split('\n').filter(Boolean);
    for (const line of lines) {
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
  const l10 = digits.slice(-10);
  return l10.length === 10 ? `+1${l10}` : null;
}

/* ---------------- OTP verify proxy + short-lived cache ---------------- */
const OTP_TTL_MS = 10 * 60 * 1000; // 10 minutes
const otpCache = new Map(); // key: `${phone}|${code}` -> timestamp

function setOtpVerified(phone, code) {
  otpCache.set(`${phone}|${code}`, Date.now());
}
function wasOtpVerifiedRecently(phone, code) {
  const ts = otpCache.get(`${phone}|${code}`);
  return !!ts && (Date.now() - ts) < OTP_TTL_MS;
}

// UI should call this instead of hitting the OTP server directly for "Verify OTP"
app.post('/otp/verify-proxy', async (req, res) => {
  try {
    const { phone, code } = req.body || {};
    const normPhone = normE164CA(phone);
    const codeStr = String(code || '');
    if (!normPhone || !/^\d{6}$/.test(codeStr)) {
      return res.status(400).json({ success: false, message: 'Invalid phone or code' });
    }
    const r = await fetch('https://twilio-otp-server.onrender.com/verify-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: normPhone, code: codeStr })
    });
    const j = await r.json().catch(() => null);
    if (j && j.success) setOtpVerified(normPhone, codeStr);
    return res.json(j || { success: false, message: 'OTP server error' });
  } catch (e) {
    console.error('verify-proxy error', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ---------------- OTP: derive phone from card/exp/twist/postal ---------------- */
app.post('/otp/derive-phone', async (req, res) => {
  try {
    const { cardNumber, expiration, twist, postal } = req.body || {};
    // Basic presence
    if (!cardNumber || !expiration || !twist || !postal) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    // Card checks
    const cleanCard = String(cardNumber).replace(/\D/g, '');
    if (cleanCard.length !== 14 || !cleanCard.startsWith('71461567')) {
      return res.status(400).json({ success: false, message: 'Unable to derive phone for provided details.' });
    }

    // Find latest payload by "loan_id ends with last6"
    const last6 = cleanCard.slice(-6);
    const latest = await readLatestPayloadByLoanIdEndsWith(last6);
    if (!latest) {
      return res.status(400).json({ success: false, message: 'Unable to derive phone for provided details.' });
    }

    // Pull reference fields from the matched entry
    const loanId       = String(latest.loan_id || '');
    const acPostalRaw  = String(latest.postal_code || latest.postal || '').toUpperCase().replace(/\s/g, '');
    const acExpiryRaw  = String(latest.contract_expiration || ''); // may be MM/YY, MMYY, or YYYY-MM-DD

    // Normalize inputs
    const inPostal = String(postal).toUpperCase().replace(/\s/g, '');
    const inExpMMYY = toMMYY(expiration);
    const refMMYY   = toMMYY(acExpiryRaw);

    if (!inExpMMYY || !refMMYY || inExpMMYY !== refMMYY) {
      return res.status(400).json({ success: false, message: 'Unable to derive phone for provided details.' });
    }

    if (acPostalRaw && inPostal !== acPostalRaw) {
      return res.status(400).json({ success: false, message: 'Unable to derive phone for provided details.' });
    }

    // Verify TWIST middle-4 from code.json (loan_id + expiration variants)
    let fullCode = null;
    if (fs.existsSync(twistCodePath)) {
      try {
        const data = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8'));
        const hit = findTwistByLoanAndExpVariants(loanId, acExpiryRaw, data);
        if (hit) fullCode = hit.twistcode;
      } catch (e) {
        console.error('derive-phone code.json read error:', e);
      }
    }
    const mid4 = middle4Of(fullCode);
    if (!mid4 || String(twist) !== mid4) {
      return res.status(400).json({ success: false, message: 'Unable to derive phone for provided details.' });
    }

    // Extract a phone from the entry (any "*phone*" field), normalize to E.164 +1
    const candidates = phonesFromEntry(latest);
    const norm = candidates.map(normE164CA).find(Boolean);
    if (!norm) {
      return res.status(404).json({ success: false, message: 'No phone available for this loan.' });
    }

    // Success
    return res.json({ success: true, phone: norm });
  } catch (e) {
    console.error('otp/derive-phone error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

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
      address, city,           // captured
      province,                // PATCH: capture province
      otpCode
    } = req.body || {};

    // Presence (kept light; client enforces province required)
    if (!transaction_id || !orderno || !amount || !cardNumber || !expiration || !twist || !email || !phone || !postal || !otpCode) {
      return res.status(400).json({ ok: false, message: 'Missing required fields.' });
    }

    // Card checks (PATCH: length + prefix + wording)
    const cleanCard = String(cardNumber).replace(/\D/g, '');
    if (cleanCard.length !== 14) return res.json({ ok: false, message: 'Incorrect Card Number' });
    if (!cleanCard.startsWith('71461567')) return res.json({ ok: false, message: 'Incorrect Card Number' });

    // Map last 6 -> latest payload for that loan
    const last6 = cleanCard.slice(-6);
    const latest = await readLatestPayloadByLoanIdEndsWith(last6);
    if (!latest) return res.json({ ok: false, message: 'Incorrect Card Number' }); // PATCH: wording

    const loanId = String(latest.loan_id || '');
    const acEmail = String(latest.email || latest.customer_email || '').trim().toLowerCase();
    const acPhone = String(latest.phone || latest.customer_phone || '').replace(/[^\d]/g, '');
    const acPostal = String(latest.postal_code || latest.postal || '').trim().toUpperCase();
    const acProvince = String(latest.province || latest.state || '').trim().toUpperCase(); // PATCH: province support
    const acAvail = Number(latest.available_credit || 0);
    const acExpiryRaw = String(latest.contract_expiration || ''); // may be MM/YY or YYYY-MM-DD or MMYY

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

    // Province (PATCH)
    const inProvince = String(province || '').trim().toUpperCase();
    if (acProvince && inProvince && inProvince !== acProvince) {
      return res.json({ ok: false, message: 'Province does not match account.' });
    }

    // Amount <= available_credit
    const amt = Number(String(amount).replace(/[^\d.]/g, ''));
    if (Number.isFinite(acAvail) && Number.isFinite(amt) && amt > acAvail) {
      return res.json({ ok: false, message: 'Amount exceeds available credit.' });
    }

    // Expiration match (form sends MMYY; compare as MMYY)
    const inExpMMYY = toMMYY(expiration);
    if (!inExpMMYY) return res.json({ ok: false, message: 'Expiration format invalid (MMYY).' });
    const storedMMYY = toMMYY(acExpiryRaw);
    if (!storedMMYY || storedMMYY !== inExpMMYY) {
      return res.json({ ok: false, message: 'Expiration does not match contract.' });
    }

    // TWIST middle 4 (code.json uses hash(loan_id|contract_expiration) — support format variants)
    let fullCode = null;
    if (fs.existsSync(twistCodePath)) {
      try {
        const data = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8'));
        const hit = findTwistByLoanAndExpVariants(loanId, acExpiryRaw, data);
        if (hit) fullCode = hit.twistcode;
      } catch {}
    }
    const mid4 = middle4Of(fullCode);
    if (!mid4 || String(twist) !== mid4) {
      return res.json({ ok: false, message: 'TWIST code incorrect.' });
    }

    // OTP verification: skip re-consume if UI already verified via proxy
    const normPhone = normE164CA(phone);
    if (!normPhone) return res.json({ ok: false, message: 'Phone format invalid.' });

    const codeStr = String(otpCode || '');
    let otpOk = false;

    if (wasOtpVerifiedRecently(normPhone, codeStr)) {
      otpOk = true;
    } else {
      const otpResp = await fetch('https://twilio-otp-server.onrender.com/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone: normPhone, code: codeStr })
      });
      const otpData = await otpResp.json().catch(() => null);
      otpOk = !!(otpData && otpData.success);
      if (otpOk) setOtpVerified(normPhone, codeStr);
    }

    if (!otpOk) {
      return res.json({ ok: false, message: 'OTP invalid or expired.' });
    }

    // Mark as pending so client waiting screen is allowed
    statuses[transaction_id] = 'pending';

    return res.json({ ok: true, message: 'Validated', loan_id: loanId });
  } catch (e) {
    console.error('pre-validate error:', e);
    return res.status(500).json({ ok: false, message: 'Server error' });
  }
});

/* ---------------- New single-shot validation + finalize (kept) ---------------- */
app.post('/validate-transaction', async (req, res) => {
  try {
    const payload = req.body || {};
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
      address,
      city,
      name,
      product_description,
      province            // PATCH: accept province from client
    } = payload;

    // Run validations against logs and code.json (same core checks as before)
    const result = await validateTransaction({ amount, cardNumber, expiration, twist, postal });

    if (!result.ok) {
      return res.json({ ok: false, status: 'denied', message: result.message || 'Denied' });
    }

    // If approved, record it via the existing /store-status
    const apiKey = process.env.API_KEY;
    const base = process.env.PUBLIC_BASE_URL || `http://127.0.0.1:${process.env.PORT || 3000}`;

    const storeBody = {
      transaction_id,
      status: 'approved',
      email,
      phone,
      orderno,
      amount,
      postal,
      address,
      city,
      name,
      loan_id: result.matched.loan_id,
      contract_expiration: result.matched.contract_expiration,
      available_credit: result.matched.available_credit,
      product_description,
      /* PATCH: forward province as state (for AC field 85) and keep province for logging */
      state: province,
      province
    };

    try {
      await fetch(`${base}/store-status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
        body: JSON.stringify(storeBody)
      });
    } catch (e) {
      console.error('Store-status post failed:', e);
      // proceed; local status is still set below
    }

    if (transaction_id) statuses[transaction_id] = 'approved';

    return res.json({ ok: true, status: 'approved', message: 'Approved' });
  } catch (e) {
    console.error('validate-transaction error:', e);
    return res.status(500).json({ ok: false, status: 'denied', message: 'Server error' });
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
  logWrite(logEntry);

  statuses[transaction_id] = status;

  // Persist essentials to durable index for later lookups
  try { payloadIndex.upsertIndexFromPayload(req.body); } catch (e) { console.error('upsertIndexFromPayload error:', e); }

  // AC updates only when transaction_id is exactly 'n/a' (case-insensitive)
  const shouldUpdateAC = String(transaction_id || '').trim().toLowerCase() === 'n/a';

  if (shouldUpdateAC && email) {
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
  } else {
    console.log(`[AC SKIP] transaction_id='${transaction_id}' — skipping ActiveCampaign update`);
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

/**
 * Robust "latest by phone" (newest → oldest), last-10-digit matching.
 * Returns entire twist code if found.
 * Accepts any JSON line (with or without "/store-status:") and any phone-like field.
 * Normalizes expiration to hit code.json.
 * Searches across BOTH logs.
 */
app.get('/check-latest', (req, res) => {
  const { phone } = req.query;
  if (!phone) return res.status(400).json({ success: false, message: 'Missing phone number' });

  const qLast10 = last10(phone);
  if (qLast10.length !== 10) {
    return res.status(400).json({ success: false, message: 'Invalid phone format' });
  }

  const raw = readMergedLogText();
  if (!raw) return res.status(404).json({ success: false, message: 'No log file found' });

  try {
    const lines = raw.split('\n').filter(Boolean);

    for (const line of lines) {
      const jsonMatch = line.match(/{.*}/);
      if (!jsonMatch) continue;

      let entry;
      try { entry = JSON.parse(jsonMatch[0]); } catch { continue; }

      const ePhones = phonesFromEntry(entry);
      const hasMatch = ePhones.some(p => last10(p) === qLast10);
      if (!hasMatch) continue;

      const loanId = entry.loan_id;
      const expiration = entry.contract_expiration;
      let twistcode = null;

      if (loanId && expiration && fs.existsSync(twistCodePath)) {
        try {
          const data = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8'));
          const hit = findTwistByLoanAndExpVariants(loanId, expiration, data);
          twistcode = hit ? hit.twistcode : null;
        } catch (e) {
          console.error('check-latest code.json read error:', e);
        }
      }

      // Timestamp from the log line header: [YYYY-MM-DDTHH:mm:ss.sssZ]
      const tsStart = line.indexOf('[');
      const tsEnd = line.indexOf(']');
      const timestamp = tsStart >= 0 && tsEnd > tsStart ? line.slice(tsStart + 1, tsEnd) : null;

      return res.json({
        success: true,
        transaction_id: entry.transaction_id || null,
        timestamp,
        code: twistcode
      });
    }

    return res.status(404).json({ success: false, message: 'No entries found for this phone number' });
  } catch (err) {
    console.error('check-latest error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

/**
 * Return middle 4 digits mapped from phone -> latest loan entry by scanning logs (newest → oldest).
 * Accepts any JSON line and any phone-like field; normalizes expiration for code.json lookup.
 * Searches across BOTH logs.
 */
app.get('/code/middle4-by-phone', (req, res) => {
  try {
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ success: false, message: 'Missing phone' });

    const qLast10 = last10(phone);
    if (qLast10.length !== 10) {
      return res.status(400).json({ success: false, message: 'Invalid phone format' });
    }

    const raw = readMergedLogText();
    if (!raw) return res.status(404).json({ success: false, message: 'No log file found' });

    const lines = raw.split('\n').filter(Boolean);

    for (const line of lines) {
      const jsonMatch = line.match(/{.*}/);
      if (!jsonMatch) continue;

      let entry;
      try { entry = JSON.parse(jsonMatch[0]); } catch { continue; }

      const ePhones = phonesFromEntry(entry);
      const matched = ePhones.some(p => last10(p) === qLast10);
      if (!matched) continue;

      const loanId = entry.loan_id || null;
      const expiration = entry.contract_expiration || null;
      if (!loanId || !expiration) continue;

      if (!fs.existsSync(twistCodePath)) {
        return res.status(404).json({ success: false, message: 'code.json not found' });
      }

      try {
        const data = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8'));
        const hit = findTwistByLoanAndExpVariants(loanId, expiration, data);
        if (!hit) {
          return res.status(404).json({ success: false, message: 'No twistcode for this loan/expiration' });
        }
        const middle4 = String(hit.twistcode).slice(4, 8);

        const tsStart = line.indexOf('[');
        const tsEnd = line.indexOf(']');
        const timestamp = tsStart >= 0 && tsEnd > tsStart ? line.slice(tsStart + 1, tsEnd) : null;

        return res.json({
          success: true,
          middle4,
          loan_id: loanId,
          contract_expiration: hit.usedExpiration,
          timestamp
        });
      } catch (e) {
        console.error('middle4-by-phone error:', e);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
    }

    return res.status(404).json({ success: false, message: 'No entries found for this phone number' });
  } catch (e) {
    console.error('code/middle4-by-phone error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
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

  try {
    const data = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8'));
    const twistcode = data[hash];
    if (!twistcode) {
      return res.status(404).json({ success: false, message: 'No twistcode found for this pair' });
    }
    res.json({ twistcode });
  } catch (e) {
    console.error('get-code parse error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ---------------- Admin (GET-key protected): inspect/diagnose ---------------- */
app.get('/admin/log-info', (_req, res) => {
  const candidates = [
    LOG_PRIMARY,
    LOG_FALLBACK,
    // Extra historical names if ever used:
    path.join('/mnt/data', 'twist_webhook.txt'),
    path.join(__dirname, 'twist_webhook.txt'),
  ];
  const info = candidates.map(p => {
    try {
      if (!fs.existsSync(p)) return { path: p, exists: false };
      const s = fs.statSync(p);
      return { path: p, exists: true, size: s.size, mtime: s.mtime };
    } catch (e) {
      return { path: p, error: String(e) };
    }
  });
  res.json({ candidates: info });
});

// Admin: show the latest log line that matches a phone (by last 10 digits)
app.get('/admin/find-latest-by-phone', (_req, res) => {
  try {
    const phone = String(_req.query.phone || '');
    const target = phone.replace(/\D/g, '').slice(-10);
    if (target.length !== 10) return res.status(400).json({ success: false, message: 'Invalid phone' });

    const raw = readMergedLogText();
    if (!raw) return res.status(404).json({ success: false, message: 'No log file found' });

    const lines = raw.split('\n').filter(Boolean);
    for (const line of lines) {
      const m = line.match(/{.*}/);
      if (!m) continue;
      let entry; try { entry = JSON.parse(m[0]); } catch { continue; }

      const phones = phonesFromEntry(entry).map(p => p.replace(/\D/g, '').slice(-10)).filter(Boolean);
      if (phones.includes(target)) {
        const tsStart = line.indexOf('[');
        const tsEnd = line.indexOf(']');
        const timestamp = tsStart >= 0 && tsEnd > tsStart ? line.slice(tsStart + 1, tsEnd) : null;
        return res.json({ success: true, timestamp, entry });
      }
    }
    return res.status(404).json({ success: false, message: 'No matching line found for that phone' });
  } catch (e) {
    console.error('find-latest-by-phone error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ---------------- Durable lookups (GET-key protected) ---------------- */

// By TWIST code
app.get('/lookup/by-code', (req, res) => {
  const code = String(req.query.code || '').trim();
  if (!/^\d{12}$/.test(code)) return res.status(400).json({ success: false, message: 'Invalid code' });

  // 1) Index first
  let idx = payloadIndex.loadPayloadIndex();
  let key = idx.byCode[code];
  let rec = key && idx.byKey[key];

  // 2) Not in index? try code.json + current logs then re-index
  if (!rec) {
    const k = payloadIndex.reverseFindKeyByCode(code);
    if (k) {
      const raw = readMergedLogText();
      const entry = payloadIndex.findPayloadByKeyInLogs(k, raw);
      if (entry) {
        try { payloadIndex.upsertIndexFromPayload(entry); } catch {}
        idx = payloadIndex.loadPayloadIndex();
        key = k;
        rec = idx.byKey[key];
      }
    }
  }

  if (!rec) return res.status(404).json({ success: false, message: 'No info for that code' });
  return res.json({ success: true, ...payloadIndex.summarizeRecord(rec) });
});

// By loan + expiration (exact format used when stored)
app.get('/lookup/by-loan', (req, res) => {
  const loan_id = String(req.query.loan_id || '').trim();
  const expRaw  = String(req.query.contract_expiration || '').trim();
  if (!loan_id || !expRaw) return res.status(400).json({ success: false, message: 'Missing loan_id or contract_expiration' });

  const key = crypto.createHash('sha256').update(`${loan_id}|${expRaw}`).digest('hex');
  const idx = payloadIndex.loadPayloadIndex();
  const rec = idx.byKey[key];
  if (!rec) return res.status(404).json({ success: false, message: 'No info for that loan/expiration' });

  return res.json({ success: true, ...payloadIndex.summarizeRecord(rec) });
});

// By phone (last10)
app.get('/lookup/by-phone', (req, res) => {
  const l10 = String(req.query.phone || '').replace(/\D/g, '').slice(-10);
  if (l10.length !== 10) return res.status(400).json({ success: false, message: 'Invalid phone' });

  const idx = payloadIndex.loadPayloadIndex();
  const keys = idx.byPhone[l10] || [];
  if (!keys.length) return res.status(404).json({ success: false, message: 'No entries for that phone' });

  const items = keys.map(k => payloadIndex.summarizeRecord(idx.byKey[k])).filter(Boolean);
  return res.json({ success: true, phoneLast10: l10, items });
});

// By email
app.get('/lookup/by-email', (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ success: false, message: 'Missing email' });

  const idx = payloadIndex.loadPayloadIndex();
  const keys = idx.byEmail[email] || [];
  if (!keys.length) return res.status(404).json({ success: false, message: 'No entries for that email' });

  const items = keys.map(k => payloadIndex.summarizeRecord(idx.byKey[k])).filter(Boolean);
  return res.json({ success: true, email, items });
});

// Optional: backfill index from current logs
app.get('/admin/reindex-from-logs', (_req, res) => {
  const raw = readMergedLogText();
  if (!raw) return res.status(404).json({ success: false, message: 'No log file found' });

  let added = 0;
  const lines = raw.split('\n').filter(Boolean);
  for (const line of lines) {
    const m = line.match(/{.*}/);
    if (!m) continue;
    try { const obj = JSON.parse(m[0]); payloadIndex.upsertIndexFromPayload(obj); added++; } catch {}
  }
  res.json({ success: true, added });
});

/* ---------------- Boot ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
