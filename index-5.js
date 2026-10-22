const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const crypto = require('crypto');
const { Telegraf, Markup } = require('telegraf');
const { Client } = require('ssh2');
const { execSync, spawn } = require('child_process');
const http = require('http');
const { WebSocketServer } = require('ws');
const config = require('./config');

if (!config.BOT_TOKEN) throw new Error('BOT_TOKEN belum diisi');
if (!config.ADMIN_IDS.length) throw new Error('ADMIN_IDS belum diisi');
if (!config.ENCRYPT_KEY) throw new Error('ENCRYPT_KEY belum diisi');

const bot = new Telegraf(config.BOT_TOKEN);

/* ===================== Konfigurasi Web Terminal ===================== */
const WEB_PORT = config.WEB_PORT || 8080;
const WEB_HOST = config.WEB_HOST || '0.0.0.0';
// Isi WEB_PUBLIC_URL di config.js kalau bot host punya domain/IP publik atau ada reverse proxy HTTPS,
// contoh: 'https://terminal.domainmu.com' atau 'http://203.0.113.10:8080'
const WEB_PUBLIC_URL = config.WEB_PUBLIC_URL || null;
const WEB_TOKEN_TTL = (config.WEB_TOKEN_TTL || 5) * 60 * 1000; // menit -> ms

/* ===================== Penyimpanan ===================== */
fs.mkdirSync(config.DATA_DIR, { recursive: true });
const DB_FILE = path.join(config.DATA_DIR, 'vps.json');
const KEY = crypto.createHash('sha256').update(config.ENCRYPT_KEY).digest();
const CLOUDFLARED_BIN = path.join(config.DATA_DIR, 'cloudflared');

function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {
    return {};
  }
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), enc].map((b) => b.toString('base64')).join('.');
}
function decrypt(payload) {
  const [iv, tag, enc] = payload.split('.').map((s) => Buffer.from(s, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
}

const getList = (uid) => loadDB()[uid] || [];
const findVps = (uid, id) => getList(uid).find((v) => v.id === id);

function upsertVps(uid, vps) {
  const db = loadDB();
  const list = db[uid] || [];
  const idx = list.findIndex(
    (v) => v.host === vps.host && v.port === vps.port && v.username === vps.username
  );
  if (idx >= 0) {
    vps.id = list[idx].id;
    list[idx] = vps;
  } else {
    list.push(vps);
  }
  db[uid] = list;
  saveDB(db);
  return vps;
}
function removeVps(uid, id) {
  const db = loadDB();
  db[uid] = (db[uid] || []).filter((v) => v.id !== id);
  saveDB(db);
}

/* ===================== Helper ===================== */
const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const sanitize = (s) => String(s).replace(/'/g, "'\\''");

function label(list, vps) {
  const samePort = list.filter((v) => v.port === vps.port).length;
  return samePort > 1 ? `VPS Port ${vps.port} (${vps.host})` : `VPS Port ${vps.port}`;
}

function trimOutput(s) {
  s = (s || '').trim();
  if (s.length > config.MAX_OUTPUT) s = '...' + s.slice(-config.MAX_OUTPUT);
  return s || '(tidak ada output)';
}

const SSH_MAX_PACKET = 64 * 1024 * 1024; // 64MB biar aman

function sshConnectOpts(vps) {
  return {
    host: vps.host,
    port: vps.port,
    username: vps.username,
    password: vps.password,
    readyTimeout: config.SSH_READY_TIMEOUT,
    algorithms: {
      compress: ['none'],
    },
  };
}

function runSSH(vps, command, timeout = config.CMD_TIMEOUT) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let done = false;
    const finish = (fn, val) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { conn.end(); } catch {}
      fn(val);
    };
    const timer = setTimeout(
      () => finish(reject, new Error('Timeout: perintah terlalu lama')),
      timeout + config.SSH_READY_TIMEOUT
    );

    conn
      .on('ready', () => {
        conn.exec(command, { maxPacketSize: SSH_MAX_PACKET }, (err, stream) => {
          if (err) return finish(reject, err);
          let stdout = '';
          let stderr = '';
          stream
            .on('close', (code) => finish(resolve, { code, stdout, stderr }))
            .on('data', (d) => (stdout += d))
            .stderr.on('data', (d) => (stderr += d));
        });
      })
      .on('error', (e) => finish(reject, e))
      .connect(sshConnectOpts(vps));
  });
}

function uploadFile(vps, localPath, remotePath) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let done = false;
    const finish = (fn, val) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { conn.end(); } catch {}
      fn(val);
    };
    const timer = setTimeout(
      () => finish(reject, new Error('Timeout upload file ke VPS')),
      120000 + config.SSH_READY_TIMEOUT
    );
    conn
      .on('ready', () => {
        conn.sftp((err, sftp) => {
          if (err) return finish(reject, err);
          sftp.fastPut(localPath, remotePath, (e) => (e ? finish(reject, e) : finish(resolve)));
        });
      })
      .on('error', (e) => finish(reject, e))
      .connect(sshConnectOpts(vps));
  });
}

const withPass = (vps) => ({ ...vps, password: decrypt(vps.password) });

function downloadFile(url, destPath, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          if (redirectsLeft <= 0) return reject(new Error('Terlalu banyak redirect'));
          return resolve(downloadFile(res.headers.location, destPath, redirectsLeft - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error('Download gagal, HTTP ' + res.statusCode));
        }
        const out = fs.createWriteStream(destPath);
        res.pipe(out);
        out.on('finish', () => out.close(resolve));
        out.on('error', reject);
      })
      .on('error', reject);
  });
}

/* ===================== Cloudflare Tunnel (lokal, untuk Web Terminal) ===================== */
async function ensureCloudflared() {
  if (fs.existsSync(CLOUDFLARED_BIN)) return CLOUDFLARED_BIN;
  if (process.platform !== 'linux') {
    throw new Error(`Auto-download cloudflared cuma didukung di Linux (host bot: ${process.platform})`);
  }
  let arch;
  if (process.arch === 'x64') arch = 'amd64';
  else if (process.arch === 'arm64') arch = 'arm64';
  else throw new Error(`Arsitektur ${process.arch} belum didukung untuk auto-download cloudflared`);

  const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}`;
  await downloadFile(url, CLOUDFLARED_BIN);
  fs.chmodSync(CLOUDFLARED_BIN, 0o755);
  return CLOUDFLARED_BIN;
}

const cfTunnel = { proc: null, url: null, starting: null };

function startCloudflareTunnel() {
  if (cfTunnel.url && cfTunnel.proc && !cfTunnel.proc.killed) {
    return Promise.resolve(cfTunnel.url);
  }
  if (cfTunnel.starting) return cfTunnel.starting;

  cfTunnel.starting = (async () => {
    const bin = await ensureCloudflared();
    return new Promise((resolve, reject) => {
      const proc = spawn(bin, ['tunnel', '--no-autoupdate', '--url', `http://localhost:${WEB_PORT}`]);
      let resolved = false;
      let buf = '';

      const onData = (d) => {
        buf += d.toString();
        const m = buf.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
        if (m && !resolved) {
          resolved = true;
          cfTunnel.proc = proc;
          cfTunnel.url = m[0];
          resolve(m[0]);
        }
      };
      proc.stdout.on('data', onData);
      proc.stderr.on('data', onData);

      proc.on('exit', () => {
        cfTunnel.proc = null;
        cfTunnel.url = null;
        if (!resolved) reject(new Error('cloudflared keluar sebelum link didapat'));
      });
      proc.on('error', (e) => {
        if (!resolved) reject(e);
      });

      setTimeout(() => {
        if (!resolved) {
          try { proc.kill(); } catch {}
          reject(new Error('Timeout menunggu link dari cloudflared'));
        }
      }, 30000);
    });
  })();

  cfTunnel.starting.finally(() => {
    cfTunnel.starting = null;
  });
  return cfTunnel.starting;
}

function stopCloudflareTunnel() {
  if (cfTunnel.proc) {
    try { cfTunnel.proc.kill(); } catch {}
  }
  cfTunnel.proc = null;
  cfTunnel.url = null;
}

async function safeEdit(ctx, text, extra) {
  try {
    await ctx.editMessageText(text, { parse_mode: 'HTML', ...extra });
  } catch (e) {
    if (!String(e.message).includes('message is not modified')) {
      await ctx.reply(text, { parse_mode: 'HTML', ...extra });
    }
  }
}

/* ===================== Backup feature ===================== */
async function createBackupAndSend(ctx) {
  const tmpDir = os.tmpdir();
  const zipPath = path.join(tmpDir, `backup-${Date.now()}.zip`);
  try {
    execSync(
      `zip -r "${zipPath}" . -x "*/node_modules/*" "*/npm/*" "*/cache/*"`,
      { cwd: __dirname, stdio: ['ignore', 'pipe', 'pipe'] }
    );
    for (const adminId of config.ADMIN_IDS) {
      try {
        await ctx.telegram.sendDocument(adminId, { source: zipPath, filename: `backup-${Date.now()}.zip` }, {
          caption: '💾 Backup file bot (excluding node_modules, npm, cache)'
        });
      } catch (e) {
        console.error(`Gagal mengirim backup ke admin ${adminId}:`, e);
      }
    }
    await ctx.reply('✅ Backup dibuat dan dikirim ke admin.');
  } catch (err) {
    await ctx.reply(`❌ Gagal membuat backup: ${err.message}`);
  } finally {
    try { fs.unlinkSync(zipPath); } catch {}
  }
}

/* ===================== Admin only ===================== */
bot.use((ctx, next) => {
  const id = ctx.from && ctx.from.id;
  if (!config.ADMIN_IDS.includes(id)) {
    if (ctx.callbackQuery) return ctx.answerCbQuery('Akses ditolak', { show_alert: true });
    return ctx.reply('⛔ Kamu bukan admin bot ini.');
  }
  return next();
});

/* ===================== State ===================== */
const states = new Map();

/* ===================== Web Terminal ===================== */
const webTokens = new Map(); // token -> { uid, vpsId, expiresAt }

function createWebToken(uid, vpsId) {
  const token = crypto.randomBytes(24).toString('hex'); // 48 karakter hex
  webTokens.set(token, { uid, vpsId, expiresAt: Date.now() + WEB_TOKEN_TTL });
  return token;
}

setInterval(() => {
  const now = Date.now();
  for (const [t, v] of webTokens) {
    if (now > v.expiresAt) webTokens.delete(t);
  }
}, 60000).unref();

function terminalPage(token) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Web Terminal VPS</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />
<style>
  html,body{margin:0;padding:0;background:#1e1e1e;height:100%;}
  #terminal{position:absolute;top:28px;left:0;right:0;bottom:0;padding:4px;box-sizing:border-box;}
  #status{position:fixed;top:0;left:0;right:0;height:24px;line-height:24px;padding:0 8px;
          font:12px monospace;color:#ddd;background:#2d2d2d;z-index:10;}
</style>
</head>
<body>
<div id="status">Menghubungkan...</div>
<div id="terminal"></div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
<script>
  const term = new Terminal({ cursorBlink: true, fontSize: 14, theme: { background: '#1e1e1e' } });
  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(document.getElementById('terminal'));
  fitAddon.fit();

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(proto + '://' + location.host + '/ws/${token}');
  const status = document.getElementById('status');

  ws.onopen = () => { status.textContent = '🟢 Terhubung'; sendResize(); };
  ws.onclose = () => { status.textContent = '🔴 Terputus (token sekali pakai, muat ulang untuk sesi baru dari bot)'; };
  ws.onerror = () => { status.textContent = '⚠️ Error koneksi'; };
  ws.onmessage = (ev) => term.write(ev.data);

  term.onData((data) => { if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'data', data })); });

  function sendResize() {
    fitAddon.fit();
    if (ws.readyState === 1) {
      ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
    }
  }
  window.addEventListener('resize', sendResize);
</script>
</body>
</html>`;
}

const webServer = http.createServer((req, res) => {
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    res.writeHead(400);
    return res.end('Bad request');
  }
  const m = url.pathname.match(/^\/term\/([a-f0-9]{48})$/);
  if (m) {
    const data = webTokens.get(m[1]);
    if (!data || Date.now() > data.expiresAt) {
      res.writeHead(410, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Link kedaluwarsa atau tidak valid. Minta link baru dari bot (tombol Web Terminal).');
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(terminalPage(m[1]));
  }
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found');
});

const wss = new WebSocketServer({ noServer: true });

webServer.on('upgrade', (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    socket.destroy();
    return;
  }
  const m = url.pathname.match(/^\/ws\/([a-f0-9]{48})$/);
  const data = m && webTokens.get(m[1]);
  if (!data || Date.now() > data.expiresAt) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, data, m[1]);
  });
});

wss.on('connection', (ws, tokenData, token) => {
  webTokens.delete(token); // token sekali pakai, langsung dicabut begitu dipakai

  const vps = findVps(tokenData.uid, tokenData.vpsId);
  if (!vps) {
    ws.send('\r\n[Error] VPS tidak ditemukan atau sudah dihapus dari bot.\r\n');
    return ws.close();
  }

  const conn = new Client();
  let sshStream = null;

  conn
    .on('ready', () => {
      conn.shell({ term: 'xterm-256color', cols: 80, rows: 24 }, (err, stream) => {
        if (err) {
          ws.send(`\r\n[Error] Gagal membuka shell: ${err.message}\r\n`);
          return ws.close();
        }
        sshStream = stream;
        stream.on('data', (d) => { if (ws.readyState === 1) ws.send(d.toString('utf8')); });
        stream.stderr.on('data', (d) => { if (ws.readyState === 1) ws.send(d.toString('utf8')); });
        stream.on('close', () => {
          try { conn.end(); } catch {}
          try { ws.close(); } catch {}
        });
      });
    })
    .on('error', (e) => {
      try { ws.send(`\r\n[Error] Koneksi SSH gagal: ${e.message}\r\n`); } catch {}
      try { ws.close(); } catch {}
    })
    .connect(sshConnectOpts(withPass(vps)));

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!sshStream) return;
    if (msg.type === 'data' && typeof msg.data === 'string') {
      sshStream.write(msg.data);
    } else if (msg.type === 'resize' && msg.cols && msg.rows) {
      try { sshStream.setWindow(msg.rows, msg.cols); } catch {}
    }
  });

  ws.on('close', () => {
    try { sshStream && sshStream.end(); } catch {}
    try { conn.end(); } catch {}
  });
});

webServer.listen(WEB_PORT, WEB_HOST, () => {
  console.log(`Web Terminal server aktif di http://${WEB_HOST}:${WEB_PORT}`);
});

bot.start((ctx) =>
  ctx.reply(
    '👋 <b>VPS Manager Bot</b>\n\n' +
      '/login - tambah & simpan VPS\n' +
      '/setting - kelola VPS yang tersimpan\n' +
      '/addscreen - upload zip & auto run di screen\n' +
      '/backup - buat backup semua file & kirim ke admin\n' +
      '/cancel - batalkan proses\n' +
      '/webtermoff - tutup tunnel Cloudflare Web Terminal\n\n' +
      '🌐 Buka /setting → pilih VPS → <b>Web Terminal</b> untuk akses SSH VPS lewat browser (otomatis dapat link publik via Cloudflare).',
    { parse_mode: 'HTML' }
  )
);

bot.command('cancel', (ctx) => {
  states.delete(ctx.from.id);
  return ctx.reply('❎ Dibatalkan.');
});

bot.command('login', (ctx) => {
  states.set(ctx.from.id, { step: 'ip', data: {} });
  return ctx.reply('🌐 Kirim <b>IP / Host VPS</b>:\n(ketik /cancel untuk batal)', {
    parse_mode: 'HTML',
  });
});

bot.command('setting', (ctx) => showList(ctx, false));

bot.command('addscreen', (ctx) => {
  const list = getList(ctx.from.id);
  if (!list.length) return ctx.reply('Belum ada VPS tersimpan. Gunakan /login dulu.');
  const rows = list.map((v) => [Markup.button.callback(label(list, v), `as:${v.id}`)]);
  return ctx.reply('📦 <b>Add Screen</b>\nPilih VPS tujuan:', {
    parse_mode: 'HTML',
    ...Markup.inlineKeyboard(rows),
  });
});

bot.command('backup', (ctx) => {
  createBackupAndSend(ctx);
});

async function showList(ctx, edit) {
  const list = getList(ctx.from.id);
  if (!list.length) {
    const t = 'Belum ada VPS tersimpan. Gunakan /login dulu.';
    return edit ? safeEdit(ctx, t) : ctx.reply(t);
  }
  const rows = list.map((v) => [Markup.button.callback(label(list, v), `v:${v.id}`)]);
  const text = '⚙️ <b>Pengaturan VPS</b>\nPilih VPS:';
  return edit
    ? safeEdit(ctx, text, Markup.inlineKeyboard(rows))
    : ctx.reply(text, { parse_mode: 'HTML', ...Markup.inlineKeyboard(rows) });
}

/* ===================== Handler teks ===================== */
bot.on('text', async (ctx) => {
  const st = states.get(ctx.from.id);
  if (!st) return;
  const text = ctx.message.text.trim();

  if (st.step === 'ip') {
    if (!/^[a-zA-Z0-9.\-]+$/.test(text)) return ctx.reply('❌ IP/Host tidak valid, coba lagi:');
    st.data.host = text;
    st.step = 'port';
    return ctx.reply('🔌 Kirim <b>port SSH</b> (contoh: 22):', { parse_mode: 'HTML' });
  }

  if (st.step === 'port') {
    const port = Number(text);
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      return ctx.reply('❌ Port tidak valid (1-65535), coba lagi:');
    st.data.port = port;
    st.step = 'user';
    return ctx.reply('👤 Kirim <b>username SSH</b> (contoh: root):', { parse_mode: 'HTML' });
  }

  if (st.step === 'user') {
    if (!/^[a-zA-Z0-9_.\-]+$/.test(text)) return ctx.reply('❌ Username tidak valid, coba lagi:');
    st.data.username = text;
    st.step = 'pass';
    return ctx.reply('🔑 Kirim <b>password SSH</b>:\n(pesan password akan dihapus otomatis)', {
      parse_mode: 'HTML',
    });
  }

  if (st.step === 'pass') {
    try { await ctx.deleteMessage(); } catch {}
    states.delete(ctx.from.id);
    const { host, port, username } = st.data;
    const wait = await ctx.reply('⏳ Mengetes koneksi SSH...');
    try {
      const r = await runSSH({ host, port, username, password: text }, 'echo ok', 10000);
      if (!r.stdout.includes('ok')) throw new Error('Respon tidak sesuai');
      const saved = upsertVps(ctx.from.id, {
        id: crypto.randomBytes(4).toString('hex'),
        host,
        port,
        username,
        password: encrypt(text),
        createdAt: Date.now(),
      });
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `✅ Koneksi berhasil & VPS disimpan.\n\nHost: ${host}\nPort: ${port}\nUser: ${username}\n\nBuka /setting untuk mengelola.`
      );
      return saved;
    } catch (e) {
      return ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `❌ Gagal terhubung: ${e.message}\n\nCek IP, port, username, password lalu coba /login lagi.`
      );
    }
  }

  if (st.step === 'cmd') {
    states.delete(ctx.from.id);
    const vps = findVps(ctx.from.id, st.data.id);
    if (!vps) return ctx.reply('VPS tidak ditemukan.');
    const wait = await ctx.reply('⏳ Menjalankan perintah...');
    try {
      const r = await runSSH(withPass(vps), text);
      const out = trimOutput(r.stdout + (r.stderr ? '\n[stderr]\n' + r.stderr : ''));
      return ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `<b>$ ${esc(text)}</b>\n<pre>${esc(out)}</pre>\nExit code: ${r.code}`,
        { parse_mode: 'HTML' }
      );
    } catch (e) {
      return ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `❌ Error: ${e.message}`
      );
    }
  }

  if (st.step === 'folder') {
    states.delete(ctx.from.id);
    const vps = findVps(ctx.from.id, st.data.id);
    if (!vps) return ctx.reply('VPS tidak ditemukan.');
    const wait = await ctx.reply('⏳ Mengecek folder...');
    try {
      const safePath = sanitize(text);
      const cmd = `if [ -d '${safePath}' ]; then echo "FOLDER_DITEMUKAN"; ls -la -- '${safePath}'; else echo "FOLDER_TIDAK_DITEMUKAN"; fi`;
      const r = await runSSH(withPass(vps), cmd);
      const out = r.stdout.trim();
      let msg = '';
      if (out.includes('FOLDER_DITEMUKAN')) {
        const contents = out.replace('FOLDER_DITEMUKAN', '').trim();
        msg = `✅ Folder <code>${esc(text)}</code> ditemukan.\nIsi folder:\n<pre>${esc(contents)}</pre>`;
      } else {
        msg = `❌ Folder <code>${esc(text)}</code> tidak ditemukan.`;
      }
      return ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        msg,
        { parse_mode: 'HTML' }
      );
    } catch (e) {
      return ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `❌ Error: ${e.message}`
      );
    }
  }

  if (st.step === 'scr_add' || st.step === 'scr_start' || st.step === 'scr_stop') {
    states.delete(ctx.from.id);
    const vps = findVps(ctx.from.id, st.data.id);
    if (!vps) return ctx.reply('VPS tidak ditemukan.');
    const wait = await ctx.reply('⏳ Memproses screen...');
    try {
      let cmd = '';
      if (st.step === 'scr_add') {
        const name = sanitize(text);
        cmd = `screen -dmS '${name}' bash`;
      } else if (st.step === 'scr_start') {
        if (text.includes(':')) {
          const [name, ...rest] = text.split(':');
          const command = rest.join(':').trim();
          const sName = sanitize(name);
          if (command) {
            const sCmd = sanitize(command);
            cmd = `screen -dmS '${sName}' bash -c '${sCmd}'`;
          } else {
            cmd = `screen -dmS '${sName}' bash`;
          }
        } else {
          const name = sanitize(text);
          cmd = `screen -dmS '${name}' bash`;
        }
      } else if (st.step === 'scr_stop') {
        const name = sanitize(text);
        cmd = `screen -S '${name}' -X quit`;
      }

      const r = await runSSH(withPass(vps), cmd);
      let out = r.stdout + (r.stderr ? '\n[stderr]\n' + r.stderr : '');
      if (r.code === 0 && !out.trim()) {
        out = st.step === 'scr_stop' ? '✅ Screen berhasil dihentikan.' : '✅ Screen berhasil dibuat.';
      }
      out = trimOutput(out);
      return ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `<b>Screen:</b> <code>${esc(text)}</code>\n<pre>${esc(out)}</pre>\nExit code: ${r.code}`,
        { parse_mode: 'HTML' }
      );
    } catch (e) {
      return ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `❌ Error: ${e.message}`
      );
    }
  }

  /* ===================== Addscreen: env input ===================== */
  if (st.step === 'addscr_env') {
    const { envKeys, envValues, currentIndex, vpsId, scrName, dir } = st.data;
    const currentKey = envKeys[currentIndex];
    envValues[currentKey] = text;

    const nextIndex = currentIndex + 1;
    if (nextIndex < envKeys.length) {
      st.data.currentIndex = nextIndex;
      const nextKey = envKeys[nextIndex];
      return ctx.reply(
        `🔑 Kirim value untuk <b>${esc(nextKey)}</b>:\n(${nextIndex + 1}/${envKeys.length})\n(ketik /cancel untuk batal)`,
        { parse_mode: 'HTML' }
      );
    }

    states.delete(ctx.from.id);
    const vps = findVps(ctx.from.id, vpsId);
    if (!vps) return ctx.reply('VPS tidak ditemukan.');
    const wait = await ctx.reply('⏳ Membuat .env dan menjalankan bot...');

    try {
      let envContent = '';
      for (const [k, v] of Object.entries(envValues)) {
        envContent += `${k}=${v}\n`;
      }
      const safeEnv = envContent.replace(/'/g, "'\\''");
      const hasStartScript = st.data.hasStartScript;
      const startCmd = hasStartScript ? 'npm start' : `node ${st.data.mainFile || 'index.js'}`;

      const cmd = [
        `cd '${sanitize(dir)}' || exit 1`,
        `printf '%s' '${safeEnv}' > .env`,
        `echo "✅ .env berhasil dibuat dengan ${envKeys.length} variabel"`,
        `screen -S '${sanitize(scrName)}' -X quit 2>/dev/null`,
        `screen -dmS '${sanitize(scrName)}' bash -c 'cd "${dir}" && ${startCmd} 2>&1'`,
        `sleep 2`,
        `echo "Screen : ${scrName}"`,
        `echo "Folder : ${dir}"`,
        `echo "Start  : ${startCmd}"`,
        `echo`,
        `screen -ls`,
      ].join('\n');

      const r = await runSSH(withPass(vps), cmd, 60000);
      const out = trimOutput(r.stdout + (r.stderr ? '\n[stderr]\n' + r.stderr : ''));
      return ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `✅ <b>Bot berhasil di-deploy!</b>\n<pre>${esc(out)}</pre>`,
        { parse_mode: 'HTML' }
      );
    } catch (e) {
      return ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `❌ Error: ${esc(e.message)}`
      );
    }
  }
});

/* ===================== Addscreen: pilih VPS ===================== */
bot.action(/^as:(\w+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const vps = findVps(ctx.from.id, ctx.match[1]);
  if (!vps) return ctx.reply('VPS tidak ditemukan.');
  states.set(ctx.from.id, { step: 'addscr_zip', data: { id: ctx.match[1] } });
  return ctx.reply(
    '📦 Kirim file <b>.zip</b> berisi script bot.\n\n' +
      'Flow otomatis:\n' +
      '1. Zip di-unzip ke VPS\n' +
      '2. <code>npm install</code> otomatis\n' +
      '3. Cek .env yang dibutuhkan\n' +
      '4. Admin isi setting yang diminta\n' +
      '5. Bot otomatis jalan di screen\n\n' +
      '(ketik /cancel untuk batal)',
    { parse_mode: 'HTML' }
  );
});

/* ===================== Remote deploy commands ===================== */
function remoteUnzipAndInstall(scrName, zipName) {
  const dir = `$HOME/bots/${scrName}`;
  const zip = `/tmp/${zipName}`;
  return {
    dir,
    cmd: [
      `command -v node >/dev/null 2>&1 || { echo "GAGAL: Node.js belum terpasang di VPS"; exit 1; }`,
      `command -v screen >/dev/null 2>&1 || { echo "GAGAL: screen belum terpasang di VPS"; exit 1; }`,
      `rm -rf "${dir}" && mkdir -p "${dir}"`,
      `if command -v unzip >/dev/null 2>&1; then unzip -o "${zip}" -d "${dir}" >/dev/null 2>&1;` +
        ` elif command -v python3 >/dev/null 2>&1; then python3 -m zipfile -e "${zip}" "${dir}";` +
        ` else echo "GAGAL: butuh unzip atau python3 di VPS"; exit 1; fi`,
      `rm -f "${zip}"`,
      `cd "${dir}" || { echo "GAGAL: masuk folder gagal"; exit 1; }`,
      `if [ "$(ls -A | wc -l)" = "1" ] && [ -d "$(ls -A | head -n1)" ]; then` +
        ` SUB="$(ls -A | head -n1)";` +
        ` mv "$SUB"/* . 2>/dev/null;` +
        ` mv "$SUB"/.[!.]* . 2>/dev/null;` +
        ` rmdir "$SUB" 2>/dev/null; fi`,
      `if [ -f package.json ]; then echo "INSTALL_START"; npm install --production 2>&1 | tail -n 5; echo "INSTALL_DONE"; fi`,
      `ENV_KEYS=""`,
      `if [ -f .env.example ]; then ENV_KEYS=$(grep -oE '^[A-Z_][A-Z0-9_]*' .env.example | sort -u | tr '\\n' ','); fi`,
      `if [ -z "$ENV_KEYS" ] && [ -f .env.template ]; then ENV_KEYS=$(grep -oE '^[A-Z_][A-Z0-9_]*' .env.template | sort -u | tr '\\n' ','); fi`,
      `if [ -z "$ENV_KEYS" ]; then ENV_KEYS=$(grep -roh 'process\\.env\\.[A-Z_][A-Z0-9_]*' *.js **/*.js 2>/dev/null | sed 's/process\\.env\\.//g' | sort -u | tr '\\n' ','); fi`,
      `if [ -f package.json ]; then`,
      `  HAS_START=$(node -e "var p=require('./package.json'); console.log(p.scripts && p.scripts.start ? 'yes' : 'no')" 2>/dev/null || echo no)`,
      `  MAIN=$(node -e "console.log(require('./package.json').main||'index.js')" 2>/dev/null || echo index.js)`,
      `else`,
      `  HAS_START=no`,
      `  MAIN=index.js`,
      `fi`,
      `[ -f "$MAIN" ] || MAIN=$(ls *.js 2>/dev/null | head -n1)`,
      `HAS_ENV=no`,
      `if [ -f .env ]; then HAS_ENV=yes; fi`,
      `echo "DEPLOY_INFO_START"`,
      `echo "DIR=${dir}"`,
      `echo "MAIN=$MAIN"`,
      `echo "HAS_START=$HAS_START"`,
      `echo "HAS_ENV=$HAS_ENV"`,
      `echo "ENV_KEYS=$ENV_KEYS"`,
      `echo "DEPLOY_INFO_END"`,
    ].join('\n'),
  };
}

function remoteStartBot(scrName, dir, startCmd) {
  return [
    `cd '${dir}' || exit 1`,
    `screen -S '${scrName}' -X quit 2>/dev/null`,
    `sleep 1`,
    `screen -dmS '${scrName}' bash -c 'cd "${dir}" && ${startCmd} 2>&1'`,
    `sleep 2`,
    `echo "Screen : ${scrName}"`,
    `echo "Folder : ${dir}"`,
    `echo "Start  : ${startCmd}"`,
    `echo`,
    `screen -ls`,
  ].join('\n');
}

/* ===================== Handler file zip (addscreen) ===================== */
bot.on('document', async (ctx) => {
  const st = states.get(ctx.from.id);
  if (!st || st.step !== 'addscr_zip') return;
  const doc = ctx.message.document;
  const fileName = doc.file_name || '';
  if (!/\.zip$/i.test(fileName)) {
    return ctx.reply('❌ File harus <b>.zip</b>. Kirim ulang atau /cancel.', { parse_mode: 'HTML' });
  }
  if (doc.file_size && doc.file_size > 20 * 1024 * 1024) {
    states.delete(ctx.from.id);
    return ctx.reply('❌ Ukuran file maksimal 20MB (batas Telegram untuk bot).');
  }
  const vpsId = st.data.id;
  const vps = findVps(ctx.from.id, vpsId);
  states.delete(ctx.from.id);
  if (!vps) return ctx.reply('VPS tidak ditemukan.');

  const wait = await ctx.reply('⏳ Mengunduh file dari Telegram...');
  try {
    const link = await ctx.telegram.getFileLink(doc.file_id);
    const url = typeof link === 'string' ? link : link.href;
    const tmpZip = path.join(os.tmpdir(), `addscr_${Date.now()}.zip`);
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmpZip);
      https.get(url, (res) => {
        if (res.statusCode !== 200) {
          out.close();
          return reject(new Error('Gagal mengunduh file (HTTP ' + res.statusCode + ')'));
        }
        res.pipe(out);
        out.on('finish', () => out.close(resolve));
      }).on('error', reject);
    });

    await ctx.telegram.editMessageText(ctx.chat.id, wait.message_id, undefined, '⏳ Mengunggah zip ke VPS...');
    const scrName =
      fileName.replace(/\.zip$/i, '').replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 30) || 'bot';
    const zipName = `addscr_${Date.now()}.zip`;
    await uploadFile(withPass(vps), tmpZip, `/tmp/${zipName}`);
    try { fs.unlinkSync(tmpZip); } catch {}

    await ctx.telegram.editMessageText(ctx.chat.id, wait.message_id, undefined, '⏳ Unzip & npm install...');
    const deploy = remoteUnzipAndInstall(scrName, zipName);
    const r = await runSSH(withPass(vps), deploy.cmd, 300000);
    const fullOutput = r.stdout + (r.stderr || '');

    if (fullOutput.includes('GAGAL:')) {
      const gagal = fullOutput.split('\n').find((l) => l.includes('GAGAL:')) || 'Unknown error';
      return ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `❌ ${esc(gagal)}`
      );
    }

    const infoMatch = fullOutput.match(/DEPLOY_INFO_START\n([\s\S]*?)DEPLOY_INFO_END/);
    let dir = '';
    let mainFile = 'index.js';
    let hasStartScript = false;
    let hasEnv = false;
    let envKeys = [];

    if (infoMatch) {
      const lines = infoMatch[1].trim().split('\n');
      for (const line of lines) {
        const [k, ...vParts] = line.split('=');
        const val = vParts.join('=');
        if (k === 'DIR') dir = val;
        if (k === 'MAIN') mainFile = val;
        if (k === 'HAS_START') hasStartScript = val === 'yes';
        if (k === 'HAS_ENV') hasEnv = val === 'yes';
        if (k === 'ENV_KEYS') {
          envKeys = val.split(',').map((s) => s.trim()).filter(Boolean);
        }
      }
    }

    if (!dir) {
      dir = `~/bots/${scrName}`;
    }

    if (envKeys.length > 0 && !hasEnv) {
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        wait.message_id,
        undefined,
        `📦 <b>Unzip & install selesai!</b>\n\n` +
          `🔑 Script butuh <b>${envKeys.length} variabel environment</b>:\n` +
          envKeys.map((k) => `  • <code>${esc(k)}</code>`).join('\n') +
          `\n\nBot akan menanyakan value satu per satu.`,
        { parse_mode: 'HTML' }
      );

      states.set(ctx.from.id, {
        step: 'addscr_env',
        data: {
          vpsId,
          scrName,
          dir,
          mainFile,
          hasStartScript,
          envKeys,
          envValues: {},
          currentIndex: 0,
        },
      });

      const firstKey = envKeys[0];
      return ctx.reply(
        `🔑 Kirim value untuk <b>${esc(firstKey)}</b>:\n(1/${envKeys.length})\n(ketik /cancel untuk batal)`,
        { parse_mode: 'HTML' }
      );
    }

    await ctx.telegram.editMessageText(ctx.chat.id, wait.message_id, undefined, '⏳ Menjalankan bot di screen...');
    const startCmd = hasStartScript ? 'npm start' : `node ${mainFile || 'index.js'}`;
    const r2 = await runSSH(withPass(vps), remoteStartBot(scrName, dir, startCmd), 60000);
    const out = trimOutput(r2.stdout + (r2.stderr ? '\n[stderr]\n' + r2.stderr : ''));
    return ctx.telegram.editMessageText(
      ctx.chat.id,
      wait.message_id,
      undefined,
      `✅ <b>Bot berhasil di-deploy!</b>\n<pre>${esc(out)}</pre>`,
      { parse_mode: 'HTML' }
    );
  } catch (e) {
    return ctx.telegram.editMessageText(
      ctx.chat.id,
      wait.message_id,
      undefined,
      `❌ Error: ${esc(e.message)}`
    );
  }
});

/* ===================== Menu per VPS ===================== */
function vpsMenu(v, list) {
  return {
    text: `🖥 <b>${esc(label(list, v))}</b>\n${esc(v.username)}@${esc(v.host)}:${v.port}`,
    kb: Markup.inlineKeyboard([
      [Markup.button.callback('📊 Info', `i:${v.id}`), Markup.button.callback('📈 Proses', `p:${v.id}`)],
      [Markup.button.callback('⌨️ Jalankan Command', `c:${v.id}`), Markup.button.callback('🔀 9Router', `n:${v.id}`)],
      [Markup.button.callback('🌐 Web Terminal', `wt:${v.id}`)],
      [Markup.button.callback('⬆️ Update (apt)', `u:${v.id}`), Markup.button.callback('🔄 Reboot', `r:${v.id}`)],
      [Markup.button.callback('🖥 Screen Manager', `sc:${v.id}`), Markup.button.callback('📁 Cek Folder', `fo:${v.id}`)],
      [Markup.button.callback('📦 Upload Bot (zip)', `as:${v.id}`)],
      [Markup.button.callback('🗑 Hapus VPS', `d:${v.id}`)],
      [Markup.button.callback('⬅️ Kembali', 's:list')],
    ]),
  };
}

bot.action('s:list', async (ctx) => {
  await ctx.answerCbQuery();
  return showList(ctx, true);
});

bot.action(/^v:(\w+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const list = getList(ctx.from.id);
  const v = list.find((x) => x.id === ctx.match[1]);
  if (!v) return safeEdit(ctx, 'VPS tidak ditemukan.');
  const m = vpsMenu(v, list);
  return safeEdit(ctx, m.text, m.kb);
});

async function runAndShow(ctx, id, title, command, timeout, backTo = 'v') {
  const v = findVps(ctx.from.id, id);
  if (!v) return ctx.answerCbQuery('VPS tidak ditemukan', { show_alert: true });
  await ctx.answerCbQuery('Menjalankan...');
  const back = Markup.inlineKeyboard([[Markup.button.callback('⬅️ Kembali', `${backTo}:${id}`)]]);
  await safeEdit(ctx, '⏳ Menjalankan...', back);
  try {
    const r = await runSSH(withPass(v), command, timeout);
    const out = trimOutput(r.stdout + (r.stderr ? '\n[stderr]\n' + r.stderr : ''));
    return safeEdit(ctx, `<b>${title}</b>\n<pre>${esc(out)}</pre>`, back);
  } catch (e) {
    return safeEdit(ctx, `❌ Error: ${esc(e.message)}`, back);
  }
}

const INFO_CMD = [
  'echo "Host   : $(hostname)"',
  'echo "OS     : $(. /etc/os-release 2>/dev/null && echo $PRETTY_NAME)"',
  'echo "Kernel : $(uname -r)"',
  'echo "Uptime : $(uptime -p 2>/dev/null)"',
  'echo "Load   : $(cut -d" " -f1-3 /proc/loadavg)"',
  'free -h | awk \'NR==2{print "RAM    : "$3" / "$2}\'',
  'df -h / | awk \'NR==2{print "Disk   : "$3" / "$2" ("$5")"}\'',
].join('; ');

bot.action(/^i:(\w+)$/, (ctx) => runAndShow(ctx, ctx.match[1], '📊 Info VPS', INFO_CMD));
bot.action(/^p:(\w+)$/, (ctx) =>
  runAndShow(ctx, ctx.match[1], '📈 Top Proses', 'ps aux --sort=-%mem | head -n 10')
);
bot.action(/^u:(\w+)$/, (ctx) =>
  runAndShow(
    ctx,
    ctx.match[1],
    '⬆️ apt update',
    'export DEBIAN_FRONTEND=noninteractive; if [ "$(id -u)" = "0" ]; then S=""; else S="sudo"; fi; $S apt-get update -y 2>&1 | tail -n 15',
    120000
  )
);

/* ===================== Folder check ===================== */
bot.action(/^fo:(\w+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  states.set(ctx.from.id, { step: 'folder', data: { id: ctx.match[1] } });
  return ctx.reply(
    '📁 Kirim <b>path folder lengkap</b> yang ingin dicek pada VPS:\n(ketik /cancel untuk batal)',
    { parse_mode: 'HTML' }
  );
});

/* ===================== Screen Manager ===================== */
bot.action(/^sc:(\w+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const id = ctx.match[1];
  const v = findVps(ctx.from.id, id);
  if (!v) return safeEdit(ctx, 'VPS tidak ditemukan.');
  return safeEdit(
    ctx,
    `🖥 <b>Screen Manager</b>\n${esc(v.username)}@${esc(v.host)}:${v.port}`,
    Markup.inlineKeyboard([
      [Markup.button.callback('📋 List Screen', `scr:list:${id}`)],
      [Markup.button.callback('➕ Add Screen', `scr:add:${id}`)],
      [Markup.button.callback('▶️ Start Command', `scr:start:${id}`)],
      [Markup.button.callback('⏹ Stop Screen', `scr:stop:${id}`)],
      [Markup.button.callback('⬅️ Kembali', `v:${id}`)],
    ])
  );
});

bot.action(/^scr:(list|start|stop|add):(\w+)$/, async (ctx) => {
  const action = ctx.match[1];
  const id = ctx.match[2];

  if (action === 'list') {
    return runAndShow(ctx, id, '📋 Daftar Screen', 'screen -ls', undefined, 'sc');
  }

  await ctx.answerCbQuery();
  let step = '';
  let prompt = '';
  if (action === 'add') {
    step = 'scr_add';
    prompt = '➕ Kirim <b>nama screen</b> baru (akan membuat screen bash kosong):';
  } else if (action === 'start') {
    step = 'scr_start';
    prompt = '▶️ Kirim <b>nama:command</b> (contoh: bot:node index.js).\nKalau cuma mau bikin screen kosong, kirim nama saja:';
  } else if (action === 'stop') {
    step = 'scr_stop';
    prompt = '⏹ Kirim <b>nama screen</b> yang mau distop:';
  }

  states.set(ctx.from.id, { step, data: { id } });
  return ctx.reply(prompt + '\n(ketik /cancel untuk batal)', { parse_mode: 'HTML' });
});

/* ===================== 9Router ===================== */
const R_PORT = 20128;
const SUDO = 'if [ "$(id -u)" = "0" ]; then S=""; SE=""; else S="sudo"; SE="sudo -E"; fi';

const INSTALL_9R = [
  'export DEBIAN_FRONTEND=noninteractive',
  SUDO,
  'NV=$(node -v 2>/dev/null | sed "s/v//;s/\\..*//")',
  'if [ -z "$NV" ] || [ "$NV" -lt 18 ]; then ' +
    '(command -v curl >/dev/null || $S apt-get install -y curl) && ' +
    'curl -fsSL https://deb.nodesource.com/setup_20.x | $SE bash - && ' +
    '$S apt-get install -y nodejs; fi',
  'command -v npm >/dev/null || { echo "GAGAL: Node.js/npm tidak terpasang (cek koneksi VPS ke internet / OS bukan Debian-Ubuntu)"; exit 1; }',
  '$S npm install -g 9router pm2 || exit 1',
  'pm2 delete 9router >/dev/null 2>&1',
  `PORT=${R_PORT} pm2 start "$(readlink -f $(which 9router))" --name 9router`,
  'pm2 save',
  'echo; echo "Node: $(node -v)"; pm2 status 9router',
].join('; ');

const DASH_ON = String.raw`
${SUDO}
curl -s -m 5 -o /dev/null http://localhost:${R_PORT} || echo "PERINGATAN: 9Router belum jalan di port ${R_PORT}. Tekan Start/Install dulu."
if [ ! -x /usr/local/bin/cloudflared ]; then
  case "$(uname -m)" in
    x86_64) A=amd64;;
    aarch64|arm64) A=arm64;;
    *) echo "GAGAL: arsitektur $(uname -m) tidak didukung"; exit 1;;
  esac
  curl -fsSL -o /tmp/cloudflared "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$A" || { echo "GAGAL: download cloudflared"; exit 1; }
  $S install -m 755 /tmp/cloudflared /usr/local/bin/cloudflared || exit 1
fi
command -v pm2 >/dev/null || { echo "GAGAL: pm2 belum terpasang, jalankan Install 9Router dulu"; exit 1; }
pm2 delete cf-9router >/dev/null 2>&1
rm -f $HOME/.pm2/logs/cf-9router-*.log
pm2 start /usr/local/bin/cloudflared --interpreter none --name cf-9router -- tunnel --no-autoupdate --url http://localhost:${R_PORT} >/dev/null 2>&1
U=""
for i in $(seq 1 25); do
  U=$(cat $HOME/.pm2/logs/cf-9router-*.log 2>/dev/null | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | tail -n1)
  [ -n "$U" ] && break
  sleep 1
done
if [ -n "$U" ]; then echo "Dashboard: $U/dashboard"; echo; echo "Ganti password bawaan (123456) setelah login!"; else echo "GAGAL dapat link. Log:"; tail -n 15 $HOME/.pm2/logs/cf-9router-*.log; fi
`;

const R_ACTIONS = {
  dash: { title: '🌐 Dashboard 9Router', cmd: DASH_ON, timeout: 120000 },
  dashoff: {
    title: '🛑 Tutup Dashboard',
    cmd: 'pm2 delete cf-9router 2>&1; echo "Link dashboard publik sudah dimatikan."',
  },
  install: { title: '⬇️ Install 9Router', cmd: INSTALL_9R, timeout: 600000 },
  start: {
    title: '▶️ Start 9Router',
    cmd: `PORT=${R_PORT} pm2 start 9router 2>&1 || PORT=${R_PORT} pm2 start "$(readlink -f $(which 9router))" --name 9router 2>&1; pm2 status 9router`,
  },
  stop: { title: '⏹ Stop 9Router', cmd: 'pm2 stop 9router 2>&1; pm2 status 9router' },
  restart: { title: '🔁 Restart 9Router', cmd: 'pm2 restart 9router 2>&1; pm2 status 9router' },
  status: { title: '📋 Status 9Router', cmd: 'pm2 status 9router 2>&1; echo; (ss -ltnp 2>/dev/null | grep -E ":' + R_PORT + '" || echo "Port ' + R_PORT + ' belum listen")' },
  logs: { title: '📜 Log 9Router', cmd: 'pm2 logs 9router --lines 25 --nostream 2>&1' },
  update: {
    title: '⬆️ Update 9Router',
    cmd: SUDO + '; $S npm install -g 9router@latest 2>&1 | tail -n 5; pm2 restart 9router 2>&1; pm2 status 9router',
    timeout: 300000,
  },
};

bot.action(/^n:(\w+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const id = ctx.match[1];
  const v = findVps(ctx.from.id, id);
  if (!v) return safeEdit(ctx, 'VPS tidak ditemukan.');
  return safeEdit(
    ctx,
    `🔀 <b>9Router</b> di ${esc(v.host)}:${v.port}\nPort aplikasi: ${R_PORT}`,
    Markup.inlineKeyboard([
      [Markup.button.callback('⬇️ Install', `nx:install:${id}`), Markup.button.callback('⬆️ Update', `nx:update:${id}`)],
      [Markup.button.callback('▶️ Start', `nx:start:${id}`), Markup.button.callback('⏹ Stop', `nx:stop:${id}`), Markup.button.callback('🔁 Restart', `nx:restart:${id}`)],
      [Markup.button.callback('📋 Status', `nx:status:${id}`), Markup.button.callback('📜 Log', `nx:logs:${id}`)],
      [Markup.button.callback('🌐 Buka Dashboard', `nx:dash:${id}`), Markup.button.callback('🛑 Tutup Dashboard', `nx:dashoff:${id}`)],
      [Markup.button.callback('🔗 Cara akses via SSH tunnel', `nx:tunnel:${id}`)],
      [Markup.button.callback('⬅️ Kembali', `v:${id}`)],
    ])
  );
});

bot.action(/^nx:(\w+):(\w+)$/, async (ctx) => {
  const [, action, id] = ctx.match;
  const v = findVps(ctx.from.id, id);
  if (!v) return ctx.answerCbQuery('VPS tidak ditemukan', { show_alert: true });

  if (action === 'tunnel') {
    await ctx.answerCbQuery();
    const cmd = `ssh -L ${R_PORT}:localhost:${R_PORT} -p ${v.port} ${v.username}@${v.host}`;
    return safeEdit(
      ctx,
      '🔗 <b>Akses dashboard lewat SSH tunnel</b>\n\nJalankan di komputermu:\n' +
        `<pre>${esc(cmd)}</pre>\nLalu buka <code>http://localhost:${R_PORT}/dashboard</code>\n\n` +
        '⚠️ Ganti password dashboard bawaan (123456) setelah login pertama.',
      Markup.inlineKeyboard([[Markup.button.callback('⬅️ Kembali', `n:${id}`)]])
    );
  }

  const a = R_ACTIONS[action];
  if (!a) return ctx.answerCbQuery('Aksi tidak dikenal');
  return runAndShow(ctx, id, a.title, a.cmd, a.timeout, 'n');
});

bot.action(/^wt:(\w+)$/, async (ctx) => {
  const id = ctx.match[1];
  const v = findVps(ctx.from.id, id);
  if (!v) return ctx.answerCbQuery('VPS tidak ditemukan', { show_alert: true });
  await ctx.answerCbQuery();

  const token = createWebToken(ctx.from.id, id);
  const ttlMin = Math.round(WEB_TOKEN_TTL / 60000);
  const header = `🌐 <b>Web Terminal</b>\n${esc(v.username)}@${esc(v.host)}:${v.port}\n\n`;
  const footer =
    `\n\n⚠️ Link hanya berlaku <b>${ttlMin} menit</b> dan hanya bisa dipakai <b>sekali</b>. ` +
    `Tekan tombol Web Terminal lagi kalau butuh link baru.`;

  // Kalau WEB_PUBLIC_URL diisi manual di config.js, pakai itu (skip cloudflared).
  if (WEB_PUBLIC_URL) {
    const link = `${WEB_PUBLIC_URL.replace(/\/$/, '')}/term/${token}`;
    return ctx.reply(
      header + `Buka link ini di browser untuk masuk terminal VPS:\n${esc(link)}` + footer,
      { parse_mode: 'HTML' }
    );
  }

  // Default: pakai Cloudflare quick tunnel, sama seperti pola 9Router.
  const wait = await ctx.reply('⏳ Menyiapkan tunnel Cloudflare untuk Web Terminal...');
  try {
    const base = await startCloudflareTunnel();
    const link = `${base}/term/${token}`;
    return ctx.telegram.editMessageText(
      ctx.chat.id,
      wait.message_id,
      undefined,
      header +
        `Buka link ini di browser (bisa dari mana saja):\n${esc(link)}` +
        footer +
        `\n\n🔒 Link publik ini cuma bisa dipakai kalau tahu token-nya (sudah tertanam di link di atas).`,
      { parse_mode: 'HTML' }
    );
  } catch (e) {
    const fallback = `http://localhost:${WEB_PORT}/term/${token}`;
    return ctx.telegram.editMessageText(
      ctx.chat.id,
      wait.message_id,
      undefined,
      `⚠️ Gagal menyiapkan tunnel Cloudflare: ${esc(e.message)}\n\n` +
        `Link fallback (cuma bisa dibuka dari komputer/server tempat bot ini jalan):\n${esc(fallback)}\n\n` +
        `Alternatif: isi <code>WEB_PUBLIC_URL</code> di config.js kalau bot punya domain/IP publik sendiri.`,
      { parse_mode: 'HTML' }
    );
  }
});

bot.command('webtermoff', (ctx) => {
  stopCloudflareTunnel();
  return ctx.reply('🛑 Tunnel Cloudflare untuk Web Terminal sudah ditutup (server web terminal tetap jalan di lokal).');
});

bot.action(/^c:(\w+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  states.set(ctx.from.id, { step: 'cmd', data: { id: ctx.match[1] } });
  return ctx.reply('⌨️ Kirim command yang mau dijalankan di VPS:\n(ketik /cancel untuk batal)');
});

bot.action(/^r:(\w+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const id = ctx.match[1];
  return safeEdit(
    ctx,
    '⚠️ Yakin mau <b>reboot</b> VPS ini?',
    Markup.inlineKeyboard([
      [Markup.button.callback('✅ Ya, reboot', `rr:${id}`), Markup.button.callback('❌ Batal', `v:${id}`)],
    ])
  );
});

bot.action(/^rr:(\w+)$/, async (ctx) => {
  const id = ctx.match[1];
  const v = findVps(ctx.from.id, id);
  if (!v) return ctx.answerCbQuery('VPS tidak ditemukan', { show_alert: true });
  await ctx.answerCbQuery('Reboot dikirim');
  const back = Markup.inlineKeyboard([[Markup.button.callback('⬅️ Kembali', `v:${id}`)]]);
  try {
    await runSSH(withPass(v), '(sudo -n true 2>/dev/null && sudo reboot) || reboot', 10000);
  } catch {}
  return safeEdit(ctx, '🔄 Perintah reboot dikirim. VPS akan online kembali beberapa saat lagi.', back);
});

bot.action(/^d:(\w+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const id = ctx.match[1];
  return safeEdit(
    ctx,
    '⚠️ Hapus VPS ini dari bot? (VPS aslinya tidak terpengaruh)',
    Markup.inlineKeyboard([
      [Markup.button.callback('🗑 Ya, hapus', `dd:${id}`), Markup.button.callback('❌ Batal', `v:${id}`)],
    ])
  );
});

bot.action(/^dd:(\w+)$/, async (ctx) => {
  await ctx.answerCbQuery('Dihapus');
  removeVps(ctx.from.id, ctx.match[1]);
  return showList(ctx, true);
});

/* ===================== Jalankan ===================== */
bot.catch((err, ctx) => console.error('Bot error:', err));
bot.launch().then(() => console.log('VPS Manager Bot aktif'));
process.once('SIGINT', () => { bot.stop('SIGINT'); webServer.close(); stopCloudflareTunnel(); });
process.once('SIGTERM', () => { bot.stop('SIGTERM'); webServer.close(); stopCloudflareTunnel(); });
