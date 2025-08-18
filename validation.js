// validation.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* ---- Paths shared with server.js ---- */
const LOG_PRIMARY = process.env.LOG_FILE_PATH || path.join('/mnt/data', 'webhook_logs.txt');
const LOG_FALLBACK = path.join(__dirname, 'webhook_logs.txt');
const twistCodePath = path.join('/mnt/data', 'code.json');

/* ---- Log helpers ---- */
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
    const s = line.indexOf('['), e = line.indexOf(']');
    const ts = (s >= 0 && e > s) ? Date.parse(line.slice(s + 1, e)) : NaN;
    return { line, idx, ts: isNaN(ts) ? null : ts };
  });

  withIndex.sort((a, b) => {
    if (a.ts !== null && b.ts !== null && a.ts !== b.ts) return b.ts - a.ts; // newest first
    return a.idx - b.idx; // stable fallback
  });

  return withIndex.map(x => x.line).join('\n');
}

function toMMYY(raw) {
  const s = String(raw || '').trim();
  let m;
  if (/^\d{4}$/.test(s)) return s; // MMYY
  if ((m = s.match(/^(\d{2})\/(\d{2})$/))) return m[1] + m[2];
  if ((m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/))) return m[2] + m[1].slice(-2);
  return null;
}
const last10 = (v) => String(v || '').replace(/\D/g, '').slice(-10);

function findLatestPayloadByLoanIdEndsWith(last6) {
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

function getMiddle4FromCodeJson(loanId, expirationRaw) {
  if (!loanId || !expirationRaw) return null;
  if (!fs.existsSync(twistCodePath)) return null;

  try {
    const map = JSON.parse(fs.readFileSync(twistCodePath, 'utf-8'));
    // Try variants for expiration (MMYY, MM/YY, YYYY-MM-DD)
    const expVariants = (() => {
      const s = String(expirationRaw || '').trim();
      const out = new Set();
      if (s) out.add(s);
      let m = s.match(/^(\d{2})\/(\d{2})$/);
      if (m) { out.add(m[1] + m[2]); out.add(m[1]+'/'+m[2]); }
      if (/^\d{4}$/.test(s)) { out.add(s); out.add(`${s.slice(0,2)}/${s.slice(2)}`); }
      m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
      if (m) {
        out.add(`${m[2]}${m[1].slice(-2)}`);
        out.add(`${m[2]}/${m[1].slice(-2)}`);
        out.add(s);
      }
      return Array.from(out);
    })();

    for (const exp of expVariants) {
      const hash = crypto.createHash('sha256').update(`${loanId}|${exp}`).digest('hex');
      const code = map[hash];
      if (code && String(code).length >= 12) return String(code).slice(4, 8);
    }
  } catch {}
  return null;
}

/**
 * Core validation:
 *  - last 6 of card => matches a loan_id in logs
 *  - expiration (MMYY) = contract_expiration
 *  - twist code middle 4 matches that loan
 *  - postal matches
 *  - available_credit >= amount
 * Returns { ok, status: 'approved'|'denied', message, matched }
 */
async function validateTransaction(payload) {
  const {
    amount, cardNumber, expiration, twist, postal
  } = payload || {};

  const cleanCard = String(cardNumber || '').replace(/\D/g, '');
  if (cleanCard.length !== 14) {
    return { ok: false, status: 'denied', message: 'Card number invalid.' };
  }

  const last6 = cleanCard.slice(-6);
  const latest = findLatestPayloadByLoanIdEndsWith(last6);
  if (!latest) {
    return { ok: false, status: 'denied', message: 'Card number invalid.' };
  }

  const loanId = String(latest.loan_id || '');
  const acPostal = String(latest.postal_code || latest.postal || '').trim().toUpperCase().replace(/\s/g, '');
  const acAvail = Number(latest.available_credit || 0);
  const acExpiryRaw = String(latest.contract_expiration || '');
  const formExpMMYY = toMMYY(expiration);
  const storedMMYY = toMMYY(acExpiryRaw);

  if (!formExpMMYY || !storedMMYY || formExpMMYY !== storedMMYY) {
    return { ok: false, status: 'denied', message: 'Expiration mismatch.' };
  }

  const mid4 = getMiddle4FromCodeJson(loanId, acExpiryRaw);
  if (!mid4 || String(twist) !== mid4) {
    return { ok: false, status: 'denied', message: 'TWIST code mismatch.' };
  }

  const inPostal = String(postal || '').trim().toUpperCase().replace(/\s/g, '');
  if (acPostal && inPostal !== acPostal) {
    return { ok: false, status: 'denied', message: 'Postal code mismatch.' };
  }

  const amt = Number(String(amount || '').replace(/[^\d.]/g, ''));
  if (!Number.isFinite(amt) || (Number.isFinite(acAvail) && amt > acAvail)) {
    return { ok: false, status: 'denied', message: 'Amount exceeds available credit.' };
  }

  return {
    ok: true,
    status: 'approved',
    message: 'Validated',
    matched: { loan_id: loanId, contract_expiration: acExpiryRaw, available_credit: acAvail }
  };
}

module.exports = { validateTransaction };
