import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import pg from "pg";
import dotenv from "dotenv";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// === PostgreSQL Verbindung ===
const { Pool } = pg;
const connectionString =
  process.env.DATABASE_URL ||
  "postgresql://postgres:postgres@localhost:5432/temple_of_logic";

const pool = new Pool({
  connectionString,
  ssl:
    connectionString.includes("railway") ||
    process.env.PGSSLMODE === "require"
      ? { rejectUnauthorized: false }
      : false,
});

// === Upload-Verzeichnis ===
const uploadDir = process.env.UPLOAD_DIR
  ? path.resolve(process.env.UPLOAD_DIR)
  : path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// === Multer Konfiguration ===
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const timestamp = Date.now();
    const sanitized = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, "_");
    cb(null, `${timestamp}-${sanitized}`);
  },
});
const upload = multer({ storage });

// === Middleware ===
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "temple-secret",
    resave: false,
    saveUninitialized: false,
  })
);

const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));
app.use("/uploads", express.static(uploadDir));

// === Hilfsfunktionen ===
const toPublicPath = (filePath) =>
  filePath ? `/uploads/${path.basename(filePath)}` : null;
const parseBoolean = (value) =>
  value === true || value === "true" || value === "on" || value === "1";

const ensureAuthenticated = (req, res, next) => {
  if (!req.session.user)
    return res.status(401).json({ error: "Nicht angemeldet" });
  next();
};
const ensureRole = (role) => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role)
    return res.status(403).json({ error: "Keine Berechtigung" });
  next();
};

// === Persönlichkeitsmerkmale & Ausrüstung ===
const CHARACTER_TRAITS = [
  "Neugierig – Stellt viele Fragen und bleibt dran",
  "Ausdauernd – Gibt nicht auf, bis die Lösung steht",
  "Kreativ – Findet ungewöhnliche Wege zum Ziel",
  "Hilfsbereit – Unterstützt andere aktiv",
  "Strukturiert – Plant Aufgaben klar durch",
  "Risikofreudig – Probiert neue Strategien aus",
  "Ruhig – Bleibt gelassen bei Fehlern",
  "Zielstrebig – Arbeitet konsequent auf das Ziel hin",
  "Analytisch – Zerlegt Probleme in kleine Teile",
  "Teamorientiert – Kooperiert gerne mit anderen",
  "Selbstkritisch – Reflektiert eigene Arbeit ehrlich",
  "Optimistisch – Sieht in jeder Aufgabe eine Chance",
  "Aufmerksam – Erkennt Details, die andere übersehen",
  "Pragmatisch – Wählt den einfachsten funktionierenden Weg",
  "Mutig – Stellt sich schwierigen Herausforderungen",
  "Sorgfältig – Achtet auf Genauigkeit",
  "Logisch denkend – Denkt Schritt für Schritt",
  "Erfinderisch – Entwickelt neue Lösungsstrategien",
  "Geduldig – Arbeitet ruhig und konzentriert auch lange",
  "Inspirierend – Motiviert andere durch eigenes Vorbild",
];

const EQUIPMENT = [
  "Zirkel der Präzision – Erhöht Genauigkeit bei Konstruktionsaufgaben",
  "Rechenamulett – Gibt +1 Fokus bei schwierigen Rechnungen",
  "Logikstein – Hilft, Muster in Zahlen zu erkennen",
  "Notizrolle der Klarheit – Ordnet Gedanken bei Textaufgaben",
  "Schutzbrille der Konzentration – Blendet Ablenkungen aus",
  "Zauberstift des Beweises – Schreibt fehlerfreie Gleichungen",
  "Kompass der Richtung – Zeigt den nächsten logischen Schritt",
  "Rucksack der Ideen – Enthält nützliche Skizzen und Tricks",
  "Lineal des Gleichgewichts – Macht Berechnungen stabiler",
  "Lampe des Einfalls – Erleuchtet kreative Lösungswege",
  "Formelbuch des Wissens – Enthält alle wichtigen Formeln",
  "Tasche der Zufälle – Kleine Hilfestellungen bei Glücksaufgaben",
  "Würfel der Wahrscheinlichkeit – Lässt dich Wahrscheinlichkeiten besser einschätzen",
  "Chronometer der Geduld – Verlangsamt Stress bei Zeitdruck",
  "Mantel der Logik – Schützt vor Denkfehlern",
  "Rechenbrett des Ausgleichs – Verbessert Überblick über Zwischenschritte",
  "Trank der Übersicht – Macht komplexe Aufgaben durchschaubar",
  "Kristall des Beweises – Verstärkt mathematische Argumentation",
  "Talisman der Motivation – Gibt Energie, auch bei schwierigen Aufgaben",
  "Zauberstab des Verständnisses – Lässt komplizierte Themen leichter erscheinen",
];

// === Basisrouten ===
app.get("/", (_req, res) => res.redirect("/login"));
app.get("/login", (_req, res) => res.sendFile(path.join(publicDir, "login.html")));
app.get("/admin", ensureAuthenticated, ensureRole("admin"), (_req, res) =>
  res.sendFile(path.join(publicDir, "admin.html"))
);
app.get("/student", ensureAuthenticated, ensureRole("student"), (_req, res) =>
  res.sendFile(path.join(publicDir, "student.html"))
);

// === Login ===
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password)
    return res.status(400).json({ error: "Name und Passwort erforderlich" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE name = $1", [name]);
    if (result.rows.length === 0)
      return res.status(400).json({ error: "Benutzer nicht gefunden" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Falsches Passwort" });

    req.session.user = { id: user.id, name: user.name, role: user.role };
    res.json({ success: true, role: user.role });
  } catch (err) {
    console.error("Login Fehler:", err);
    res.status(500).json({ error: "Serverfehler beim Login" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// === Initialisiere Datenbank ===
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      xp INTEGER DEFAULT 0,
      highest_xp INTEGER DEFAULT 0
    )
  `);

  const adminHash = await bcrypt.hash("admin", 10);
  await pool.query(
    `INSERT INTO users (name, password, role)
     VALUES ($1, $2, 'admin')
     ON CONFLICT (name) DO UPDATE SET role = 'admin'`,
    ["admin", adminHash]
  );
}

// === Start ===
initDatabase()
  .then(() => {
    app.listen(PORT, () => console.log(`✅ Server läuft auf Port ${PORT}`));
  })
  .catch((error) => {
    console.error("❌ Fehler beim Initialisieren der Datenbank:", error);
    process.exit(1);
  });

