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

/**
 * Robust log handling:
 * - Primary path from env LOG_FILE_PATH or defaults to /mnt/data/webhook_logs.txt (persistent on Render)
 * - Fallback path in app directory ./webhook_logs.txt
 * - Touch primary on boot; read from whichever exists/newest; write to both when possible.
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
function readLogText() {
  const candidates = [];
  try { if (fs.existsSync(LOG_PRIMARY)) candidates.push({ p: LOG_PRIMARY, s: fs.statSync(LOG_PRIMARY).size, m: fs.statSync(LOG_PRIMARY).mtimeMs }); } catch {}
  try { if (fs.existsSync(LOG_FALLBACK)) candidates.push({ p: LOG_FALLBACK, s: fs.statSync(LOG_FALLBACK).size, m: fs.statSync(LOG_FALLBACK).mtimeMs }); } catch {}
  if (candidates.length === 0) return null;
  candidates.sort((a, b) => b.m - a.m);
  const chosen = candidates.find(c => c.s > 0) || candidates[0];
  try { return fs.readFileSync(chosen.p, 'utf-8'); } catch (e) {
    console.error('readLogText error:', e);
    return null;
  }
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

/* --------- Phone + expiration utilities for resilient matching --------- */
// collect all phone-like fields from a log entry
function phonesFromEntry(entry) {
  if (!entry || typeof entry !== 'object') return [];
  const out = [];
  for (const [k, v] of Object.entries(entry)) {
    if (/phone/i.test(k) && typeof v === 'string') out.push(v);
  }
  return out;
}
// last 10 digits comparator
const last10 = (v) => String(v || '').replace(/\D/g, '').slice(-10);
// normalize expiration into multiple candidate formats
function expCandidates(v) {
  const s = String(v || '').trim();
  const out = new Set();
  if (s) out.add(s); // raw

  // MM/YY
  let m = s.match(/^(\d{2})\/(\d{2})$/);
  if (m) { out.add(`${m[1]}${m[2]}`); out.add(`${m[1]}/${m[2]}`); }

  // MMYY
  if (/^\d{4}$/.test(s)) { out.add(s); out.add(`${s.slice(0,2)}/${s.slice(2)}`); }

  // YYYY-MM-DD
  m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (m) {
    out.add(`${m[2]}${m[1].slice(-2)}`);   // MMYY
    out.add(`${m[2]}/${m[1].slice(-2)}`);  // MM/YY
    out.add(s);                            // raw
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
 * Scan newest→oldest lines in whichever log is present.
 * Accept ANY line that contains a JSON object (old logs might not have "/store-status:" marker).
 */
async function readLatestPayloadByLoanIdEndsWith(last6) {
  try {
    const raw = readLogText();
    if (!raw) return null;
    const lines = raw.split('\n').filter(Boolean).reverse(); // newest -> oldest
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
  logWrite(logEntry);

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

/**
 * Robust "latest by phone" (newest → oldest), last-10-digit matching.
 * Returns entire twist code if found.
 * Accepts any JSON line (with or without "/store-status:") and any phone-like field.
 * Normalizes expiration to hit code.json.
 */
app.get('/check-latest', (req, res) => {
  const { phone } = req.query;
  if (!phone) return res.status(400).json({ success: false, message: 'Missing phone number' });

  const qLast10 = last10(phone);
  if (qLast10.length !== 10) {
    return res.status(400).json({ success: false, message: 'Invalid phone format' });
  }

  const raw = readLogText();
  if (!raw) return res.status(404).json({ success: false, message: 'No log file found' });

  try {
    const lines = raw.split('\n').filter(Boolean).reverse();

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
 */
app.get('/code/middle4-by-phone', (req, res) => {
  try {
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ success: false, message: 'Missing phone' });

    const qLast10 = last10(phone);
    if (qLast10.length !== 10) {
      return res.status(400).json({ success: false, message: 'Invalid phone format' });
    }

    const raw = readLogText();
    if (!raw) return res.status(404).json({ success: false, message: 'No log file found' });

    const lines = raw.split('\n').filter(Boolean).reverse();

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

    const raw = readLogText();
    if (!raw) return res.status(404).json({ success: false, message: 'No log file found' });

    const lines = raw.split('\n').filter(Boolean).reverse(); // newest → oldest
    for (const line of lines) {
      const m = line.match(/{.*}/); if (!m) continue;
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

/* ---------------- Boot ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
