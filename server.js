import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import pg from "pg";
import dotenv from "dotenv";
import multer from "multer";
import fs from "fs";
import path from "path";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL Verbindung
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("railway")
    ? { rejectUnauthorized: false }
    : false,
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "temple-secret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(express.static("public"));

// Uploads konfigurieren
const uploadDir = process.env.UPLOAD_DIR || "uploads";
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE name = $1", [
      name,
    ]);

    if (result.rows.length === 0)
      return res.status(400).json({ error: "Benutzer nicht gefunden" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Falsches Passwort" });

    req.session.user = user;
    res.json({ success: true, role: user.role });
  } catch (err) {
    console.error("Login Fehler:", err);
    res.status(500).json({ error: "Serverfehler beim Login" });
  }
});

// ---------- TEST ----------
app.get("/", (req, res) => {
  res.send("<h1>Temple of Logic läuft 🚀</h1>");
});

// ---------- SERVER ----------
app.listen(PORT, () =>
  console.log(`✅ Server läuft auf Port ${PORT}`)
);
