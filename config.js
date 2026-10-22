require('dotenv').config();
const path = require('path');

function parseAdminIds(raw) {
  if (!raw) return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map(Number)
    .filter((n) => !Number.isNaN(n));
}

function parseIntOr(raw, def) {
  const n = parseInt(raw, 10);
  return Number.isNaN(n) ? def : n;
}

module.exports = {
  // --- Wajib diisi ---
  BOT_TOKEN: process.env.BOT_TOKEN || '',
  ADMIN_IDS: parseAdminIds(process.env.ADMIN_IDS),
  ENCRYPT_KEY: process.env.ENCRYPT_KEY || '',

  // --- Penyimpanan data (vps.json, cloudflared binary, dll) ---
  DATA_DIR: process.env.DATA_DIR
    ? path.resolve(process.env.DATA_DIR)
    : path.join(__dirname, 'data'),

  // --- Perilaku eksekusi command SSH ---
  SSH_READY_TIMEOUT: parseIntOr(process.env.SSH_READY_TIMEOUT, 15000), // ms
  CMD_TIMEOUT: parseIntOr(process.env.CMD_TIMEOUT, 60000), // ms
  MAX_OUTPUT: parseIntOr(process.env.MAX_OUTPUT, 3500), // karakter, batas sebelum dipotong di pesan Telegram

  // --- Web Terminal ---
  WEB_PORT: parseIntOr(process.env.WEB_PORT, 8080),
  WEB_HOST: process.env.WEB_HOST || '0.0.0.0',
  // Isi kalau punya domain/IP publik sendiri (skip Cloudflare tunnel), contoh:
  // https://terminal.domainmu.com  atau  http://203.0.113.10:8080
  WEB_PUBLIC_URL: process.env.WEB_PUBLIC_URL || '',
  WEB_TOKEN_TTL: parseIntOr(process.env.WEB_TOKEN_TTL, 5), // menit
};
