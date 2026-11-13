const express = require("express");
const { Pool } = require("pg");
const QRCode = require("qrcode");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
const ADMIN_KEY = process.env.ADMIN_KEY || "change-me";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL. Add it in Render > Environment (the Neon connection string).");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Neon requires SSL; local test databases usually don't
  ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false },
});

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const page = (body) => `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Certificate Verification</title>
<style>body{font-family:system-ui,sans-serif;max-width:520px;margin:40px auto;padding:0 16px}
.card{border-radius:12px;padding:24px;border:2px solid}.ok{border-color:#1a7f37;background:#eafbee}
.bad{border-color:#b42318;background:#fdecea}input,button{display:block;width:100%;padding:10px;margin:8px 0;font-size:16px;box-sizing:border-box}
button{background:#111;color:#fff;border:0;border-radius:8px}</style></head><body>${body}</body></html>`;

// Make async route errors show a friendly message instead of crashing
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const newId = () => crypto.randomBytes(6).toString("hex").toUpperCase();

const requireAdmin = (req, res, next) => {
  const key = req.get("x-admin-key") || req.query.key || (req.body && req.body.key);
  if (key !== ADMIN_KEY) return res.status(401).json({ error: "Unauthorized" });
  next();
};

async function insertCert({ holder_name, title, issued_on, issuer }) {
  const id = newId();
  await pool.query(
    "INSERT INTO certificates (id, holder_name, title, issued_on, issuer) VALUES ($1,$2,$3,$4,$5)",
    [id, holder_name, title, issued_on, issuer]
  );
  return id;
}

// Front page: type an ID to check a certificate by hand
app.get("/", (req, res) => {
  res.send(page(`<h2>Verify a certificate</h2>
    <p>Scan the QR code on the certificate, or type its Certificate ID here.</p>
    <form onsubmit="location.href='/verify/'+encodeURIComponent(this.id.value.trim());return false">
    <input name="id" placeholder="Certificate ID" required><button>Verify</button></form>`));
});

// Issue a certificate (JSON API)
app.post("/api/certificates", requireAdmin, wrap(async (req, res) => {
  const { holder_name, title, issued_on, issuer } = req.body;
  if (!holder_name || !title || !issued_on || !issuer)
    return res.status(400).json({ error: "holder_name, title, issued_on, issuer are required" });
  const id = await insertCert({ holder_name, title, issued_on, issuer });
  res.status(201).json({ id, verify_url: `${BASE_URL}/verify/${id}`, qr_png: `${BASE_URL}/qr/${id}.png` });
}));

// Revoke a certificate
app.post("/api/certificates/:id/revoke", requireAdmin, wrap(async (req, res) => {
  const r = await pool.query("UPDATE certificates SET revoked=TRUE WHERE id=$1", [req.params.id.toUpperCase()]);
  res.json({ revoked: r.rowCount === 1 });
}));

// QR code image pointing to the verify page
app.get("/qr/:id.png", wrap(async (req, res) => {
  const png = await QRCode.toBuffer(`${BASE_URL}/verify/${req.params.id.toUpperCase()}`, { width: 400, margin: 2 });
  res.type("png").send(png);
}));

// Public verification page (what the QR code opens)
app.get("/verify/:id", wrap(async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM certificates WHERE id=$1", [req.params.id.toUpperCase()]);
  const c = rows[0];
  if (!c)
    return res.status(404).send(page(`<div class="card bad"><h2>❌ Not found</h2>
      <p>No certificate with this ID exists in our records. It may be fake.</p></div>`));
  if (c.revoked)
    return res.send(page(`<div class="card bad"><h2>⚠️ Revoked</h2>
      <p>Certificate <b>${esc(c.id)}</b> was issued but has been revoked and is no longer valid.</p></div>`));
  res.send(page(`<div class="card ok"><h2>✅ Genuine certificate</h2>
    <p><b>Holder:</b> ${esc(c.holder_name)}</p><p><b>Certificate:</b> ${esc(c.title)}</p>
    <p><b>Issued by:</b> ${esc(c.issuer)}</p><p><b>Date:</b> ${esc(c.issued_on)}</p>
    <p><b>ID:</b> ${esc(c.id)}</p></div>`));
}));

// Simple admin form: /admin?key=YOUR_KEY
app.get("/admin", requireAdmin, (req, res) => {
  res.send(page(`<h2>Issue certificate</h2><form method="post" action="/admin">
    <input type="hidden" name="key" value="${esc(req.query.key)}">
    <input name="holder_name" placeholder="Holder name" required>
    <input name="title" placeholder="Certificate title" required>
    <input name="issuer" placeholder="Issuer" required>
    <input name="issued_on" type="date" required><button>Generate</button></form>`));
});
app.post("/admin", requireAdmin, wrap(async (req, res) => {
  const { holder_name, title, issued_on, issuer } = req.body;
  const id = await insertCert({ holder_name, title, issued_on, issuer });
  res.send(page(`<h2>Created: ${esc(id)}</h2><img src="/qr/${id}.png" width="300" alt="QR">
    <p>Right-click to save the QR and place it on the certificate. Also print the ID next to it.</p>
    <p><a href="/verify/${id}">${esc(BASE_URL)}/verify/${id}</a></p>`));
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send(page(`<div class="card bad"><h2>Something went wrong</h2><p>Please try again in a moment.</p></div>`));
});

(async () => {
  await pool.query(`CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    holder_name TEXT NOT NULL,
    title TEXT NOT NULL,
    issued_on TEXT NOT NULL,
    issuer TEXT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  app.listen(PORT, () => console.log(`Running on ${BASE_URL}`));
})().catch((e) => {
  console.error("Could not connect to the database:", e.message);
  process.exit(1);
});
