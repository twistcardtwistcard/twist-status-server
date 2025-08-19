require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// -------------------------------
// Security: Protect ALL GET routes
// -------------------------------
app.use((req, res, next) => {
  if (req.method === 'GET') {
    const apiKey = req.headers['x-api-key'];
    const authorizedKey = process.env.GET_API_KEY;
    if (!authorizedKey) {
      console.warn('WARNING: GET_API_KEY is not set');
    }
    if (!apiKey || apiKey !== authorizedKey) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
  }
  next();
});

// In-memory transaction store (baseline behavior)
const statuses = {}; // { [transaction_id]: { status, ...payload } }
const latestByPhone = {}; // { [last10]: { ...payload, t } }

// -------------------------------------------------
// Paths & Files (Render Disk + repo fallbacks)
// -------------------------------------------------
const RENDER_DATA_DIR = '/mnt/data';
const WEBHOOK_LOG = path.join(RENDER_DATA_DIR, 'webhook_logs.txt');
const WEBHOOK_LOG_REPO = path.join(__dirname, 'webhook_logs.txt');

const CODE_DB = path.join(RENDER_DATA_DIR, 'code.json');
const CODE_DB_REPO = path.join(__dirname, 'code.json'); // fallback only for read if needed

// Candidate logs (search webhook first, then optional server logs)
const LOG_CANDIDATES = [
  WEBHOOK_LOG,                  // primary payload log (Render Disk)
  WEBHOOK_LOG_REPO,             // repo fallback
  path.join(RENDER_DATA_DIR, 'server_logs.txt'), // optional
  path.join(__dirname, 'server_logs.txt'),       // optional fallback
];

// Ensure /mnt/data exists on Render
try { fs.mkdirSync(RENDER_DATA_DIR, { recursive: true }); } catch (_) {}

// -------------------------------------
// Helpers: time, logging, safe parsing
// -------------------------------------
function nowIso() {
  return new Date().toISOString();
}

async function appendWebhookLogLine(obj) {
  const line = JSON.stringify({ t: nowIso(), ...obj }) + '\n';
  try {
    await fs.promises.appendFile(WEBHOOK_LOG, line, 'utf8');
  } catch (e) {
    console.error('Failed to append /mnt/data webhook log, trying repo file:', e.message);
    try {
      await fs.promises.appendFile(WEBHOOK_LOG_REPO, line, 'utf8');
    } catch (e2) {
      console.error('Failed to append repo webhook log:', e2.message);
    }
  }
}

function digitsOnly(v) {
  return String(v || '').replace(/\D/g, '');
}

function last10(v) {
  const d = digitsOnly(v);
  return d.slice(-10);
}

// ------------------------------------------------------
// TWIST code: load/save DB and deterministic generation
// ------------------------------------------------------
function loadCodeDb() {
  let raw = null;
  try {
    raw = fs.readFileSync(CODE_DB, 'utf8');
  } catch (_) {
    try {
      raw = fs.readFileSync(CODE_DB_REPO, 'utf8');
    } catch (_) {
      raw = null;
    }
  }
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch (e) {
    console.error('code.json parse error:', e.message);
    return {};
  }
}

function saveCodeDb(db) {
  try {
    fs.writeFileSync(CODE_DB, JSON.stringify(db, null, 2), 'utf8');
  } catch (e) {
    console.error('Failed to write code.json:', e.message);
  }
}

/**
 * Deterministic 12-digit code from loan_id + contract_expiration.
 * NOTE: Algorithm kept generic to respect prior behavior: we hash input and map bytes to digits.
 */
function generate12DigitCode(loan_id, contract_expiration) {
  const seed = `${String(loan_id || '').trim()}|${String(contract_expiration || '').trim()}`;
  const hash = crypto.createHash('sha256').update(seed).digest();
  let out = '';
  for (let i = 0; i < hash.length && out.length < 12; i++) {
    out += (hash[i] % 10).toString();
  }
  // Extremely unlikely, but ensure length 12
  while (out.length < 12) out += '0';
  return out;
}

/**
 * Get or generate + store a TWIST code for (loan_id, contract_expiration).
 * Structure:
 * {
 *   "<loan_id>|<contract_expiration>": "123456789012",
 *   last: { key: "<loan|exp>", code: "..." }
 * }
 */
function getOrGenerateTwistCode(loan_id, contract_expiration) {
  if (!loan_id || !contract_expiration) return null;
  const key = `${String(loan_id).trim()}|${String(contract_expiration).trim()}`;
  const db = loadCodeDb();
  if (db[key]) {
    // Update "last" pointer
    db.last = { key, code: db[key], t: nowIso() };
    saveCodeDb(db);
    return db[key];
  }
  const code = generate12DigitCode(loan_id, contract_expiration);
  db[key] = code;
  db.last = { key, code, t: nowIso() };
  saveCodeDb(db);
  return code;
}

// ------------------------------------------------------
// Unified log searching (webhook first, then others)
// ------------------------------------------------------
async function getReadableLogFiles() {
  const seen = new Set();
  const files = [];
  for (const p of LOG_CANDIDATES) {
    if (seen.has(p)) continue;
    seen.add(p);
    try {
      const st = await fs.promises.stat(p);
      if (st.isFile() && st.size > 0) files.push({ p, mtime: st.mtime, size: st.size });
    } catch (_) {}
  }
  // newest first
  return files.sort((a, b) => b.mtime - a.mtime).map(f => f.p);
}

/**
 * Stream through candidate logs; collect the *last* match per file; return newest file's match first.
 * @param {{ testLine: (line)=>any, max?: number }} opts
 */
async function searchLogs({ testLine, max = 1 }) {
  const results = [];
  for (const file of await getReadableLogFiles()) {
    let lineNo = 0;
    let lastMatch = null;
    const stream = fs.createReadStream(file, { encoding: 'utf8' });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    for await (const line of rl) {
      lineNo++;
      const match = testLine(line);
      if (match) lastMatch = { file, lineNo, line, match };
    }
    if (lastMatch) {
      results.push(lastMatch);
      if (results.length >= max) break;
    }
  }
  return results;
}

// ------------------------------------------------------
// ActiveCampaign helpers (kept conservative)
// ------------------------------------------------------
const AC_BASE_URL = process.env.AC_BASE_URL || '';      // e.g., https://youraccount.api-us1.com
const AC_API_KEY  = process.env.AC_API_KEY  || '';
const AC_AVAILABLE_CREDIT_FIELD_ID = process.env.AC_AVAILABLE_CREDIT_FIELD_ID || ''; // optional env for available_credit field id
const AC_PRODUCT_DESCRIPTION_FIELD_ID = '88'; // as per your baseline

async function acUpsertFieldValues({ contactId, email, fields }) {
  if (!AC_BASE_URL || !AC_API_KEY) {
    // AC not configured; just skip silently
    return { skipped: true, reason: 'AC not configured' };
    // NOTE: We do not throw to preserve baseline behavior
  }

  // Strategy: Prefer contactId if provided; otherwise use contact/sync with email.
  try {
    if (contactId) {
      // Create/update each fieldValue for contact
      // POST /api/3/fieldValues  { field: <id>, value: "...", contact: <contactId> }
      const results = [];
      for (const { field, value } of fields) {
        const resp = await fetch(`${AC_BASE_URL}/api/3/fieldValues`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Api-Token': AC_API_KEY,
          },
          body: JSON.stringify({ fieldValue: { field, value, contact: String(contactId) } }),
        });
        const data = await resp.json().catch(() => ({}));
        results.push({ field, ok: resp.ok, status: resp.status, data });
      }
      return { ok: true, mode: 'fieldValues', results };
    }

    if (email) {
      // Use contact/sync with fieldValues array
      const resp = await fetch(`${AC_BASE_URL}/api/3/contact/sync`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Api-Token': AC_API_KEY,
        },
        body: JSON.stringify({
          contact: {
            email: String(email).trim(),
            fieldValues: fields.map(({ field, value }) => ({ field, value })),
          },
        }),
      });
      const data = await resp.json().catch(() => ({}));
      return { ok: resp.ok, status: resp.status, data, mode: 'contact/sync' };
    }

    return { skipped: true, reason: 'no contactId or email' };
  } catch (err) {
    console.error('ActiveCampaign update error:', err.message);
    return { ok: false, error: err.message };
  }
}

async function updateActiveCampaignFromPayload(payload = {}) {
  // Respect baseline: update available_credit (if present) and product_description (field 88)
  const fields = [];
  if (payload.hasOwnProperty('available_credit')) {
    const fieldId = String(payload.available_credit_field_id || AC_AVAILABLE_CREDIT_FIELD_ID || '').trim();
    if (fieldId) fields.push({ field: fieldId, value: String(payload.available_credit) });
  }
  if (payload.hasOwnProperty('product_description')) {
    fields.push({ field: AC_PRODUCT_DESCRIPTION_FIELD_ID, value: String(payload.product_description) });
  }
  if (!fields.length) return { skipped: true, reason: 'no fields to update' };

  const contactId =
    payload.active_campaign_contact_id ||
    payload.ac_contact_id ||
    payload.contact_id ||
    null;

  const email = payload.email || payload.contact_email || null;

  return acUpsertFieldValues({ contactId, email, fields });
}

// ------------------------------------------------------
// Static form (kept as baseline behavior)
// ------------------------------------------------------
// Serve /public if present
app.use(express.static(path.join(__dirname, 'public')));

// Direct route for the form HTML if you keep it at /public/twistpay-form.html
app.get('/twistpay-form', (req, res) => {
  const candidate = path.join(__dirname, 'public', 'twistpay-form.html');
  if (fs.existsSync(candidate)) {
    return res.sendFile(candidate);
  }
  // Fallback (rare): simple note to avoid breaking embed completely
  res.type('html').send(`
    <!doctype html>
    <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TWIST Card Payment</title></head>
    <body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:1rem">
      <p>Form file <code>public/twistpay-form.html</code> not found.</p>
    </body></html>
  `);
});

// ------------------------------------------------------
// POST /store-status  (baseline: API-key protected)
// ------------------------------------------------------
app.post('/store-status', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const authorizedKey = process.env.POST_API_KEY || process.env.GET_API_KEY; // allow fallback to GET key if desired
  if (!authorizedKey) {
    console.warn('WARNING: POST_API_KEY/GET_API_KEY is not set');
  }
  if (!apiKey || apiKey !== authorizedKey) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const payload = req.body || {};

    // Normalize/derive handy fields
    const transaction_id = String(payload.transaction_id || payload.txn_id || payload.id || '').trim();
    const phoneLast10 = last10(payload.phone || payload.client_phone || payload.customer_phone || '');
    const loan_id = String(payload.loan_id || '').trim();
    const contract_expiration = String(payload.contract_expiration || payload.expiration || '').trim();

    // In-memory stores (baseline)
    if (transaction_id) statuses[transaction_id] = { ...payload, t: nowIso() };
    if (phoneLast10) latestByPhone[phoneLast10] = { ...payload, t: nowIso() };

    // Generate/store TWIST code if we have loan_id + contract_expiration
    let twistcode = null;
    if (loan_id && contract_expiration) {
      twistcode = getOrGenerateTwistCode(loan_id, contract_expiration);
    }

    // Append to webhook log on Render Disk (baseline)
    await appendWebhookLogLine({ type: 'store-status', transaction_id, phoneLast10, loan_id, contract_expiration, twistcode, payload });

    // Update ActiveCampaign (baseline: available_credit and product_description id 88)
    const acResult = await updateActiveCampaignFromPayload(payload);

    return res.json({
      success: true,
      stored: Boolean(transaction_id || phoneLast10),
      transaction_id,
      phoneLast10,
      twistcode,
      ac: acResult,
    });
  } catch (err) {
    console.error('POST /store-status error:', err);
    return res.status(500).json({ success: false, message: 'Internal error' });
  }
});

// ------------------------------------------------------
// GET /get-code?loan_id=...&contract_expiration=...
// ------------------------------------------------------
app.get('/get-code', async (req, res) => {
  try {
    const { loan_id, contract_expiration } = req.query || {};
    if (!loan_id || !contract_expiration) {
      return res.status(400).json({ success: false, message: 'loan_id and contract_expiration are required' });
    }
    const twistcode = getOrGenerateTwistCode(loan_id, contract_expiration);

    // Log the lookup
    await appendWebhookLogLine({ type: 'get-code', loan_id, contract_expiration, twistcode });

    return res.json({ success: true, twistcode });
  } catch (err) {
    console.error('GET /get-code error:', err);
    return res.status(500).json({ success: false, message: 'Internal error' });
  }
});

// ------------------------------------------------------
// GET /check-status?transaction_id=...
//  - First check in-memory; fallback to logs
// ------------------------------------------------------
app.get('/check-status', async (req, res) => {
  try {
    const transaction_id = String(req.query.transaction_id || '').trim();
    if (!transaction_id) {
      return res.status(400).json({ success: false, message: 'transaction_id is required' });
    }

    if (statuses[transaction_id]) {
      return res.json({ success: true, source: 'memory', data: statuses[transaction_id] });
    }

    // Fallback: try to find the last log line containing the transaction_id
    const re = new RegExp(`"transaction_id"\\s*:\\s*"${transaction_id}"|"txn_id"\\s*:\\s*"${transaction_id}"|"id"\\s*:\\s*"${transaction_id}"`);
    const hits = await searchLogs({
      testLine: (line) => (re.test(line) ? { transaction_id } : null),
      max: 1,
    });

    if (hits.length) {
      return res.json({ success: true, source: hits[0].file, hint: 'match in logs', matchLine: hits[0].line });
    }

    return res.status(404).json({ success: false, message: 'Not found' });
  } catch (err) {
    console.error('GET /check-status error:', err);
    return res.status(500).json({ success: false, message: 'Internal error' });
  }
});

// ------------------------------------------------------
// GET /last-update-by-phone?phone=...
//  - Uses in-memory latest; fallback to logs
// ------------------------------------------------------
app.get('/last-update-by-phone', async (req, res) => {
  try {
    const l10 = last10(req.query.phone || '');
    if (!l10) return res.status(400).json({ success: false, message: 'phone is required' });

    if (latestByPhone[l10]) {
      return res.json({ success: true, source: 'memory', phoneLast10: l10, data: latestByPhone[l10] });
    }

    const re = new RegExp(`\\b${l10}\\b`);
    const hits = await searchLogs({
      testLine: (line) => (re.test(line) ? { l10 } : null),
      max: 1,
    });

    if (hits.length) {
      return res.json({
        success: true,
        source: hits[0].file,
        phoneLast10: l10,
        matchLine: hits[0].line,
      });
    }

    return res.status(404).json({ success: false, message: 'No matching line' });
  } catch (err) {
    console.error('GET /last-update-by-phone error:', err);
    return res.status(500).json({ success: false, message: 'Internal error' });
  }
});

// ------------------------------------------------------
// GET /check-latest
//  - Prefer code.json (baseline), fall back to webhook/server logs
// ------------------------------------------------------
app.get('/check-latest', async (req, res) => {
  try {
    // 1) Prefer durable store
    try {
      const raw = await fs.promises.readFile(CODE_DB, 'utf8');
      const db = JSON.parse(raw || '{}');
      if (db && db.last && db.last.code) {
        return res.json({ ok: true, source: 'code.json', code: db.last.code });
      }
    } catch (_) {
      // ignore and fall through
    }

    // 2) Fallback: search logs for a 12-digit code
    const hits = await searchLogs({
      testLine: (line) => {
        const m = line.match(/"(?:twistcode|code)"\s*:\s*"(\d{12})"/);
        return m ? { code: m[1] } : null;
      },
      max: 1,
    });

    if (hits.length) {
      return res.json({ ok: true, source: hits[0].file, code: hits[0].match.code });
    }

    return res.status(404).json({ ok: false, msg: 'No code found in code.json or logs' });
  } catch (err) {
    console.error('check-latest error:', err);
    return res.status(500).json({ ok: false, msg: 'Internal error' });
  }
});

// ------------------------------------------------------
// OPTIONAL: Debug route for Postman - latest line by phone
// ------------------------------------------------------
app.get('/debug/find-by-phone', async (req, res) => {
  const l10 = last10(req.query.phone || '');
  if (!l10) return res.status(400).json({ ok: false, msg: 'phone query param required' });

  try {
    const re = new RegExp(`\\b${l10}\\b`);
    const hits = await searchLogs({
      testLine: (line) => (re.test(line) ? { l10 } : null),
      max: 1,
    });
    return res.json({ ok: true, last10: l10, hits });
  } catch (err) {
    console.error('find-by-phone error:', err);
    return res.status(500).json({ ok: false, msg: 'Internal error' });
  }
});

// -------------------------------------
// Start server
// -------------------------------------
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
