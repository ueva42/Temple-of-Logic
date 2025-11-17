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
app.use(express.static("public"));

const upload = multer();


// =====================================================
// ADMIN MIDDLEWARE
// =====================================================
function authAdmin(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).send("Kein Token");

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin")
      return res.status(403).send("Keine Adminrechte");

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send("Token ungültig");
  }
}


// =====================================================
// LOGIN
// =====================================================
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;

  if (!name || !password)
    return res.status(400).send("Name oder Passwort fehlt");

  const r = await query(`SELECT * FROM users WHERE name=$1`, [name]);
  if (r.rowCount === 0) return res.status(400).send("User nicht gefunden");

  const user = r.rows[0];

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).send("Passwort falsch");

  const token = jwt.sign(
    { id: user.id, name: user.name, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "3h" }
  );

  res.send({ token, role: user.role });
});


// =====================================================
// DATEI-UPLOAD (R2)
// =====================================================
app.post("/upload", authAdmin, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).send("Keine Datei");

  const key = `uploads/${Date.now()}-${req.file.originalname}`;

  const url = await uploadToR2(
    key,
    req.file.mimetype,
    req.file.buffer
  );

  res.send({ url });
});


// =====================================================
// KLASSENVERWALTUNG
// =====================================================
app.get("/api/classes", authAdmin, async (req, res) => {
  const r = await query("SELECT * FROM classes ORDER BY name");
  res.send(r.rows);
});

app.post("/api/classes", authAdmin, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).send("Name fehlt");

  try {
    await query(`INSERT INTO classes (name) VALUES ($1)`, [name]);
    res.send("Klasse angelegt");
  } catch (err) {
    res.status(400).send("Fehler: Klasse existiert vielleicht schon");
  }
});

app.delete("/api/classes/:id", authAdmin, async (req, res) => {
  await query(`DELETE FROM classes WHERE id=$1`, [req.params.id]);
  res.send("Klasse gelöscht");
});


// =====================================================
// NOTFALL: ADMIN HARD RESET
// Aufruf: /api/reset-admin
// =====================================================
app.get("/api/reset-admin", async (req, res) => {
  try {
    const pw = "bruhrain";
    const hash = await bcrypt.hash(pw, 10);

    const r = await query(`SELECT id FROM users WHERE name='admin'`);

    if (r.rowCount === 0) {
      await query(
        `INSERT INTO users (name, password, role) VALUES ('admin', $1, 'admin')`,
        [hash]
      );
      return res.send("Admin NEU angelegt: admin / bruhrain");
    }

    await query(
      `UPDATE users SET password=$1, role='admin' WHERE name='admin'`,
      [hash]
    );

    res.send("Admin zurückgesetzt: admin / bruhrain");
  } catch (err) {
    console.error(err);
    res.status(500).send("Fehler beim Reset");
  }
});


// =====================================================
// MIGRATION
// =====================================================
async function migrate() {
  console.log("🔧 Migration startet...");

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

  console.log("✔ Migration abgeschlossen");
}


// =====================================================
// START + ADMIN FIX
// =====================================================
async function ensureAdmin() {
  console.log("🔧 Prüfe Admin...");

  const hash = await bcrypt.hash("bruhrain", 10);

  const r = await query(`SELECT id FROM users WHERE name='admin'`);

  if (r.rowCount === 0) {
    await query(
      `INSERT INTO users (name, password, role) VALUES ('admin', $1, 'admin')`,
      [hash]
    );
    console.log("✔ Admin angelegt: admin / bruhrain");
  } else {
    await query(
      `UPDATE users SET password=$1, role='admin' WHERE name='admin'`,
      [hash]
    );
    console.log("✔ Admin-Passwort aktualisiert: bruhrain");
  }
}

async function start() {
  await migrate();
  await ensureAdmin();

  app.listen(PORT, () =>
    console.log(`🚀 Server läuft auf Port ${PORT}`)
  );
}

start();
