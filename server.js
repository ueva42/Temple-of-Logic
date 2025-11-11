import express from "express";
import session from "express-session";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Datenbank initialisieren
const db = new sqlite3.Database("temple.db");

// Upload-Verzeichnis anlegen
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ dest: uploadDir });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: "temple-secret",
  resave: false,
  saveUninitialized: false
}));
app.use(express.static(path.join(__dirname, "public")));

// --- LOGIN ------------------------------------------------------
app.post("/api/login", (req, res) => {
  const { name, password } = req.body;
  db.get("SELECT * FROM users WHERE name = ?", [name], async (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(400).json({ error: "Benutzer nicht gefunden" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Falsches Passwort" });
    req.session.user = { id: user.id, role: user.role, class_id: user.class_id };
    res.json({ role: user.role });
  });
});

// --- ADMINBEREICH ------------------------------------------------
app.get("/api/classes", (req, res) => {
  db.all("SELECT * FROM classes", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// --- Standardseiten ----------------------------------------------
app.get("/", (_, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/admin", (_, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/student", (_, res) => res.sendFile(path.join(__dirname, "public", "student.html")));

// --- SERVER START ------------------------------------------------
app.listen(PORT, () => console.log(`Temple of Logic läuft auf Port ${PORT}`));
