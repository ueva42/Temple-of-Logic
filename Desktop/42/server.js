// server.js
import express from "express";
import multer from "multer";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { query } from "./db.js";
import { uploadToR2 } from "./r2.js";

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json());
app.use(express.static("public")); // login.html + admin.html etc.

const upload = multer();


// =====================================================
// AUTH MIDDLEWARE – nur Admin
// =====================================================
function authAdmin(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).send("Kein Token");

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin")
      return res.status(403).send("Keine Admin-Rechte");

    req.user = decoded;
    next();
  } catch {
    res.status(401).send("Token ungültig");
  }
}


// =====================================================
// BASIS ROUTEN
// =====================================================
app.get("/", (req, res) => {
  res.redirect("/login.html");
});


// =====================================================
// LOGIN SYSTEM
// =====================================================
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;

  if (!name || !password)
    return res.status(400).send("Name oder Passwort fehlt");

  const result = await query(`SELECT * FROM users WHERE name=$1`, [name]);
  if (result.rowCount === 0) return res.status(400).send("User nicht gefunden");

  const user = result.rows[0];

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).send("Passwort falsch");

  if (!process.env.JWT_SECRET)
    return res.status(500).send("JWT_SECRET fehlt!");

  const token = jwt.sign(
    {
      id: user.id,
      role: user.role,
      name: user.name,
    },
    process.env.JWT_SECRET,
    { expiresIn: "3h" }
  );

  res.send({ token, role: user.role });
});


// =====================================================
// DATEI-UPLOAD – CLOUDFLARE R2
// =====================================================
app.post("/upload", authAdmin, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).send("Keine Datei übergeben");

  const key = `uploads/${Date.now()}-${req.file.originalname}`;
  const url = await uploadToR2(key, req.file.mimetype, req.file.buffer);

  res.send({ url });
});


// =====================================================
// ADMIN: KLASSENVERWALTUNG
// =====================================================

// Klassen anzeigen
app.get("/api/classes", authAdmin, async (req, res) => {
  const r = await query(`SELECT * FROM classes ORDER BY name`);
  res.send(r.rows);
});

// Klasse anlegen
app.post("/api/classes", authAdmin, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).send("Name fehlt");

  try {
    await query(`INSERT INTO classes (name) VALUES ($1)`, [name]);
    res.send("Klasse angelegt");
  } catch {
    res.status(400).send("Fehler: Klasse existiert vielleicht schon");
  }
});

// Klasse löschen
app.delete("/api/classes/:id", authAdmin, async (req, res) => {
  const id = req.params.id;
  await query(`DELETE FROM classes WHERE id=$1`, [id]);
  res.send("Klasse gelöscht");
});


// =====================================================
// MIGRATION – ALLE TABELLEN
// =====================================================
async function migrate() {
  console.log("Starte Migration...");

  await query(`
    CREATE TABLE IF NOT EXISTS vars (
      id SERIAL PRIMARY KEY,
      key TEXT UNIQUE NOT NULL,
      value TEXT NOT NULL
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
      xp INTEGER NOT NULL DEFAULT 0,
      highest_xp INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS missions (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      xp INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS xp_transactions (
      id SERIAL PRIMARY KEY,
      student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      awarded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      xp INTEGER NOT NULL,
      reason TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS student_mission_uploads (
      id SERIAL PRIMARY KEY,
      student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      mission_id INTEGER REFERENCES missions(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  console.log("Migration abgeschlossen");
}


// =====================================================
// ADMIN REPARIEREN / ANLEGEN
// =====================================================
async function ensureAdmin() {
  console.log("Prüfe Admin...");

  const adminPw = "bruhrain";
  const hash = await bcrypt.hash(adminPw, 10);

  const r = await query(`SELECT * FROM users WHERE name='admin'`);

  if (r.rowCount === 0) {
    console.log("⚠️ Kein Admin gefunden – lege neuen Admin an…");

    await query(
      `INSERT INTO users (name, password, role) VALUES ('admin', $1, 'admin')`,
      [hash]
    );

    console.log("✔ Admin angelegt: admin / bruhrain");
  } else {
    console.log("⚠️ Admin vorhanden – setze Passwort neu…");

    await query(
      `UPDATE users SET password=$1, role='admin' WHERE name='admin'`,
      [hash]
    );

    console.log("✔ Admin-Passwort aktualisiert: bruhrain");
  }
}


// =====================================================
// START SERVER
// =====================================================
async function start() {
  await migrate();
  await ensureAdmin();

  app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}`);
  });
}

start();
