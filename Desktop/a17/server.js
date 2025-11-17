// server.js
import "dotenv/config";
import express from "express";
import session from "express-session";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import { migrate, query } from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret-temple-key",
    resave: false,
    saveUninitialized: false
  })
);

// Static
app.use(express.static(path.join(__dirname, "public")));

// --- Helper
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login.html");
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role)
      return res.status(403).send("Forbidden");
    next();
  };
}

// --- ROOT
app.get("/", (req, res) => res.redirect("/login.html"));

// --- LOGIN
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const r = await query("SELECT * FROM users WHERE name=$1", [username]);
  const user = r.rows[0];

  if (!user || user.password !== password) {
    return res.status(400).json({ error: "Falscher Benutzername oder Passwort" });
  }

  req.session.user = { id: user.id, name: user.name, role: user.role };

  res.json({ ok: true, role: user.role });
});

app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Nicht eingeloggt" });
  res.json(req.session.user);
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// -----------------------------------------
// ADMIN: Klassen
// -----------------------------------------
app.get("/api/classes", requireLogin, requireRole("admin"), async (req, res) => {
  const all = await query("SELECT * FROM classes ORDER BY id ASC");
  const active = await query("SELECT value FROM settings WHERE key='active_class'");
  res.json({
    classes: all.rows,
    active_class: active.rows[0]?.value || null
  });
});

app.post("/api/classes", requireLogin, requireRole("admin"), async (req, res) => {
  const { name } = req.body;
  try {
    await query("INSERT INTO classes (name) VALUES ($1)", [name]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: "Klasse existiert bereits" });
  }
});

app.delete("/api/classes/:id", requireLogin, requireRole("admin"), async (req, res) => {
  const { id } = req.params;
  await query("DELETE FROM classes WHERE id=$1", [id]);
  res.json({ ok: true });
});

app.post("/api/classes/active", requireLogin, requireRole("admin"), async (req, res) => {
  const { id } = req.body;
  await query("UPDATE settings SET value=$1 WHERE key='active_class'", [id]);
  res.json({ ok: true });
});

// -----------------------------------------
// Views
// -----------------------------------------
app.get("/admin", requireLogin, requireRole("admin"), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/student", requireLogin, requireRole("student"), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "student.html"));
});

// -----------------------------------------

migrate().then(() => {
  app.listen(PORT, () => console.log("Server läuft auf Port " + PORT));
});
