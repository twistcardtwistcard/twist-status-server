// lib/payloadIndex.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PAYLOAD_INDEX = path.join('/mnt/data', 'payload_index.json');
const twistCodePath = path.join('/mnt/data', 'code.json');

const last10 = (v) => String(v || '').replace(/\D/g, '').slice(-10);

function loadJsonSafe(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf-8')); } catch (_) { return null; }
}

// MUST match server.js logic for determinism/compat
function getOrGenerateTwistCode(loanId, expiration) {
  if (!loanId || !expiration) return null;
  const hash = crypto.createHash('sha256').update(`${loanId}|${expiration}`).digest('hex');
  let data = loadJsonSafe(twistCodePath) || {};
  if (data[hash]) return data[hash];
  const newCode = Array.from({ length: 12 }, () => Math.floor(Math.random() * 10)).join('');
  data[hash] = newCode;
  fs.writeFileSync(twistCodePath, JSON.stringify(data, null, 2));
  return newCode;
}

// ---- index IO ----
function loadPayloadIndex() {
  const j = loadJsonSafe(PAYLOAD_INDEX) || {};
  return {
    byKey: j.byKey || {},     // key=sha256(loan|exp) -> {loan_id, contract_expiration, code, phones, emails, lastPayload, updatedAt}
    byCode: j.byCode || {},   // code -> key
    byPhone: j.byPhone || {}, // last10 -> [key,...]
    byEmail: j.byEmail || {}, // email -> [key,...]
  };
}
function savePayloadIndex(idx) {
  try { fs.writeFileSync(PAYLOAD_INDEX, JSON.stringify(idx, null, 2)); } catch (e) {
    console.error('savePayloadIndex error:', e);
  }
}

// Upsert from a full payload object (typically req.body from /store-status)
function upsertIndexFromPayload(payload) {
  if (!payload) return;
  const loan_id = String(payload.loan_id || '').trim();
  const exp     = String(payload.contract_expiration || '').trim();
  if (!loan_id || !exp) return;

  const key  = crypto.createHash('sha256').update(`${loan_id}|${exp}`).digest('hex');
  const code = getOrGenerateTwistCode(loan_id, exp);

  const phoneLast10 = last10(payload.phone || payload.customer_phone || payload.client_phone || '');
  const email = String(payload.email || payload.customer_email || '').trim().toLowerCase();

  const idx = loadPayloadIndex();
  const rec = idx.byKey[key] || { loan_id, contract_expiration: exp, code, phones: {}, emails: {}, lastPayload: null, updatedAt: null };

  if (phoneLast10) rec.phones[phoneLast10] = true;
  if (email) rec.emails[email] = true;
  rec.lastPayload = payload;
  rec.updatedAt = new Date().toISOString();

  idx.byKey[key] = rec;
  idx.byCode[code] = key;

  if (phoneLast10) {
    if (!idx.byPhone[phoneLast10]) idx.byPhone[phoneLast10] = [];
    if (!idx.byPhone[phoneLast10].includes(key)) idx.byPhone[phoneLast10].push(key);
  }
  if (email) {
    if (!idx.byEmail[email]) idx.byEmail[email] = [];
    if (!idx.byEmail[email].includes(key)) idx.byEmail[email].push(key);
  }

  savePayloadIndex(idx);
}

// Reverse-find sha256(loan|exp) key by code from code.json
function reverseFindKeyByCode(code) {
  if (!/^\d{12}$/.test(String(code))) return null;
  const data = loadJsonSafe(twistCodePath) || {};
  for (const [k, v] of Object.entries(data)) {
    if (k === 'last') continue;
    if (String(v) === String(code)) return k; // k is sha256(loan|exp)
  }
  return null;
}

// Parse a raw merged log text and find payload whose key matches sha256(loan|exp)
function findPayloadByKeyInLogs(key, rawLogText) {
  if (!rawLogText) return null;
  const lines = rawLogText.split('\n').filter(Boolean);
  for (const line of lines) {
    const m = line.match(/{.*}/);
    if (!m) continue;
    let entry; try { entry = JSON.parse(m[0]); } catch { continue; }
    const loan_id = entry.loan_id;
    const exp     = entry.contract_expiration;
    if (!loan_id || !exp) continue;
    const k = crypto.createHash('sha256').update(`${loan_id}|${exp}`).digest('hex');
    if (k === key) return entry;
  }
  return null;
}

// Pretty response formatter for admin/get endpoints
function summarizeRecord(rec) {
  if (!rec) return null;
  return {
    loan_id: rec.loan_id,
    contract_expiration: rec.contract_expiration,
    code: rec.code,
    phones: Object.keys(rec.phones || {}),
    emails: Object.keys(rec.emails || {}),
    updatedAt: rec.updatedAt,
    // lastPayload: rec.lastPayload, // uncomment if you want full payloads returned
  };
}

module.exports = {
  loadPayloadIndex,
  savePayloadIndex,
  upsertIndexFromPayload,
  reverseFindKeyByCode,
  findPayloadByKeyInLogs,
  summarizeRecord,
  last10,
};
