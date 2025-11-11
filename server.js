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

// PostgreSQL Verbindung
const { Pool } = pg;
const connectionString =
  process.env.DATABASE_URL ||
  "postgresql://postgres:postgres@localhost:5432/temple_of_logic";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("railway")
    ? { rejectUnauthorized: false }
    : false,
  connectionString,
  ssl:
    connectionString.includes("railway") || process.env.PGSSLMODE === "require"
      ? { rejectUnauthorized: false }
      : false,
});

// Middleware
const uploadDir = process.env.UPLOAD_DIR
  ? path.resolve(process.env.UPLOAD_DIR)
  : path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const timestamp = Date.now();
    const sanitized = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, "_");
    cb(null, `${timestamp}-${sanitized}`);
  },
});

const upload = multer({ storage });

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
const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));
app.use("/uploads", express.static(uploadDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
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

const toPublicPath = (filePath) =>
  filePath ? `/uploads/${path.basename(filePath)}` : null;

const parseBoolean = (value) =>
  value === true || value === 'true' || value === 'on' || value === '1';

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      is_active BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS characters (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      image_path TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
      character_id INTEGER REFERENCES characters(id) ON DELETE SET NULL,
      traits JSONB DEFAULT '[]'::jsonb,
      equipment JSONB DEFAULT '[]'::jsonb,
      xp INTEGER DEFAULT 0,
      highest_xp INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS missions (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      xp_value INTEGER NOT NULL,
      image_path TEXT,
      allow_upload BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS student_mission_uploads (
      id SERIAL PRIMARY KEY,
      mission_id INTEGER REFERENCES missions(id) ON DELETE CASCADE,
      student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      file_path TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS xp_transactions (
      id SERIAL PRIMARY KEY,
      student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      amount INTEGER NOT NULL,
      reason TEXT,
      mission_id INTEGER REFERENCES missions(id) ON DELETE SET NULL,
      awarded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS bonus_cards (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      xp_cost INTEGER NOT NULL,
      image_path TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS bonus_redemptions (
      id SERIAL PRIMARY KEY,
      bonus_card_id INTEGER REFERENCES bonus_cards(id) ON DELETE CASCADE,
      student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS levels (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      xp_threshold INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
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

const mapUserRow = (row) => ({
  id: row.id,
  name: row.name,
  role: row.role,
  classId: row.class_id,
  characterId: row.character_id,
  traits: row.traits || [],
  equipment: row.equipment || [],
  xp: Number(row.xp) || 0,
  highestXp: Number(row.highest_xp) || 0,
});

const getActiveClass = async () => {
  const { rows } = await pool.query(
    "SELECT * FROM classes WHERE is_active = TRUE LIMIT 1"
  );
  return rows[0] || null;
};

app.get("/", (_req, res) => {
  res.redirect("/login");
});

app.get("/login", (_req, res) => {
  res.sendFile(path.join(publicDir, "login.html"));
});

app.get("/admin", ensureAuthenticated, ensureRole("admin"), (_req, res) => {
  res.sendFile(path.join(publicDir, "admin.html"));
});

app.get("/student", ensureAuthenticated, ensureRole("student"), (_req, res) => {
  res.sendFile(path.join(publicDir, "student.html"));
});

app.get("/api/session", (req, res) => {
  if (!req.session.user) return res.json({ authenticated: false });
  res.json({ authenticated: true, user: req.session.user });
});
const upload = multer({ storage });

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password)
    return res.status(400).json({ error: "Name und Passwort erforderlich" });

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
    req.session.user = {
      id: user.id,
      name: user.name,
      role: user.role,
    };
    res.json({ success: true, role: user.role });
  } catch (err) {
    console.error("Login Fehler:", err);
    res.status(500).json({ error: "Serverfehler beim Login" });
  }
});

// ---------- TEST ----------
app.get("/", (req, res) => {
  res.send("<h1>Temple of Logic läuft 🚀</h1>");
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ---------- SERVER ----------
app.listen(PORT, () =>
  console.log(`✅ Server läuft auf Port ${PORT}`)
// ----- Klassen -----
app.get(
  "/api/admin/classes",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, name, is_active FROM classes ORDER BY name"
      );
      res.json(rows);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Klassen konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/admin/classes",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { name } = req.body;
    if (!name?.trim())
      return res.status(400).json({ error: "Klassenname erforderlich" });
    try {
      const { rows } = await pool.query(
        "INSERT INTO classes (name) VALUES ($1) RETURNING id, name, is_active",
        [name.trim()]
      );
      res.status(201).json(rows[0]);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Klasse konnte nicht angelegt werden" });
    }
  }
);

app.patch(
  "/api/admin/classes/:id/activate",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    try {
      await pool.query("UPDATE classes SET is_active = FALSE");
      const { rows } = await pool.query(
        "UPDATE classes SET is_active = TRUE WHERE id = $1 RETURNING id, name, is_active",
        [id]
      );
      if (!rows[0])
        return res.status(404).json({ error: "Klasse nicht gefunden" });
      res.json(rows[0]);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Klasse konnte nicht aktiviert werden" });
    }
  }
);

app.get(
  "/api/admin/classes/active",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const active = await getActiveClass();
      res.json(active);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Aktive Klasse konnte nicht geladen werden" });
    }
  }
);

// ----- Schüler:innen -----
app.get(
  "/api/admin/students",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { classId } = req.query;
    try {
      const id = classId || (await getActiveClass())?.id;
      if (!id) return res.json([]);
      const { rows } = await pool.query(
        `SELECT id, name, xp, highest_xp, traits, equipment FROM users
         WHERE role = 'student' AND class_id = $1
         ORDER BY name`,
        [id]
      );
      res.json(
        rows.map((row) => ({
          id: row.id,
          name: row.name,
          xp: Number(row.xp) || 0,
          highestXp: Number(row.highest_xp) || 0,
          traits: row.traits || [],
          equipment: row.equipment || [],
        }))
      );
    } catch (error) {
      console.error(error);
      res
        .status(500)
        .json({ error: "Schüler:innen konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/admin/students",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { name, password, classId } = req.body;
    if (!name?.trim() || !password)
      return res
        .status(400)
        .json({ error: "Name und Passwort sind erforderlich" });

    try {
      const targetClassId = classId || (await getActiveClass())?.id;
      if (!targetClassId)
        return res.status(400).json({ error: "Keine aktive Klasse ausgewählt" });
      const hash = await bcrypt.hash(password, 10);
      const { rows } = await pool.query(
        `INSERT INTO users (name, password, role, class_id)
         VALUES ($1, $2, 'student', $3)
         RETURNING id, name, xp, highest_xp, traits, equipment`,
        [name.trim(), hash, targetClassId]
      );
      const student = rows[0];
      res.status(201).json({
        id: student.id,
        name: student.name,
        xp: Number(student.xp) || 0,
        highestXp: Number(student.highest_xp) || 0,
        traits: student.traits || [],
        equipment: student.equipment || [],
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Schüler:in konnte nicht angelegt werden" });
    }
  }
);

// ----- XP Vergabe -----
app.post(
  "/api/admin/xp-awards",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { studentIds = [], amount, missionId, reason, applyToAll } = req.body;

    try {
      let targetStudents = studentIds;
      if (applyToAll) {
        const active = await getActiveClass();
        if (!active)
          return res.status(400).json({ error: "Keine aktive Klasse ausgewählt" });
        const { rows } = await pool.query(
          "SELECT id FROM users WHERE role = 'student' AND class_id = $1",
          [active.id]
        );
        targetStudents = rows.map((row) => row.id);
      }

      if (!targetStudents.length)
        return res.status(400).json({ error: "Keine Schüler:innen ausgewählt" });

      let totalAmount = Number(amount);
      if (Number.isNaN(totalAmount) || totalAmount < 0) totalAmount = 0;
      let missionXp = 0;
      if (missionId) {
        const { rows } = await pool.query(
          "SELECT xp_value FROM missions WHERE id = $1",
          [missionId]
        );
        if (!rows[0])
          return res.status(404).json({ error: "Mission nicht gefunden" });
        missionXp = Number(rows[0].xp_value) || 0;
      }

      if (!totalAmount && !missionXp)
        return res
          .status(400)
          .json({ error: "XP-Betrag oder Mission erforderlich" });

      const xpToAdd = totalAmount + missionXp;

      const awardedStudents = [];
      for (const studentId of targetStudents) {
        const { rows } = await pool.query(
          "SELECT xp, highest_xp FROM users WHERE id = $1 AND role = 'student'",
          [studentId]
        );
        if (!rows[0]) continue;
        const currentXp = Number(rows[0].xp) || 0;
        const highestXp = Number(rows[0].highest_xp) || 0;
        const newXp = currentXp + xpToAdd;
        const newHighest = Math.max(highestXp, newXp);
        await pool.query(
          "UPDATE users SET xp = $1, highest_xp = $2, updated_at = NOW() WHERE id = $3",
          [newXp, newHighest, studentId]
        );
        await pool.query(
          `INSERT INTO xp_transactions (student_id, amount, reason, mission_id, awarded_by)
           VALUES ($1, $2, $3, $4, $5)`,
          [studentId, xpToAdd, reason || null, missionId || null, req.session.user.id]
        );
        awardedStudents.push(studentId);
      }

      res.json({ success: true, studentIds: awardedStudents, xpAdded: xpToAdd });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "XP konnten nicht vergeben werden" });
    }
  }
);

// ----- Missionen -----
app.get(
  "/api/admin/missions",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, title, description, xp_value, image_path, allow_upload FROM missions ORDER BY created_at DESC"
      );
      res.json(
        rows.map((mission) => ({
          ...mission,
          xp_value: Number(mission.xp_value) || 0,
          image_path: toPublicPath(mission.image_path),
        }))
      );
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Missionen konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/admin/missions",
  ensureAuthenticated,
  ensureRole("admin"),
  upload.single("image"),
  async (req, res) => {
    const { title, description, xp_value, allow_upload } = req.body;
    if (!title?.trim() || !xp_value)
      return res
        .status(400)
        .json({ error: "Titel und XP-Wert sind erforderlich" });

    try {
      const imagePath = req.file ? req.file.path : null;
      const { rows } = await pool.query(
        `INSERT INTO missions (title, description, xp_value, image_path, allow_upload)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, title, description, xp_value, image_path, allow_upload`,
        [
          title.trim(),
          description || null,
          Number(xp_value),
          imagePath,
          parseBoolean(allow_upload),
        ]
      );
      const mission = rows[0];
      res.status(201).json({
        ...mission,
        xp_value: Number(mission.xp_value) || 0,
        image_path: toPublicPath(mission.image_path),
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Mission konnte nicht angelegt werden" });
    }
  }
);

// ----- Bonuskarten -----
app.get(
  "/api/admin/bonus-cards",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, title, description, xp_cost, image_path FROM bonus_cards ORDER BY xp_cost"
      );
      res.json(
        rows.map((card) => ({
          ...card,
          xp_cost: Number(card.xp_cost) || 0,
          image_path: toPublicPath(card.image_path),
        }))
      );
    } catch (error) {
      console.error(error);
      res
        .status(500)
        .json({ error: "Bonuskarten konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/admin/bonus-cards",
  ensureAuthenticated,
  ensureRole("admin"),
  upload.single("image"),
  async (req, res) => {
    const { title, description, xp_cost } = req.body;
    if (!title?.trim() || !xp_cost)
      return res
        .status(400)
        .json({ error: "Titel und XP-Kosten sind erforderlich" });
    try {
      const imagePath = req.file ? req.file.path : null;
      const { rows } = await pool.query(
        `INSERT INTO bonus_cards (title, description, xp_cost, image_path)
         VALUES ($1, $2, $3, $4)
         RETURNING id, title, description, xp_cost, image_path`,
        [title.trim(), description || null, Number(xp_cost), imagePath]
      );
      const card = rows[0];
      res.status(201).json({
        ...card,
        xp_cost: Number(card.xp_cost) || 0,
        image_path: toPublicPath(card.image_path),
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Bonuskarte konnte nicht angelegt werden" });
    }
  }
);

// ----- Charaktere -----
app.get(
  "/api/admin/characters",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, name, image_path FROM characters ORDER BY name"
      );
      res.json(
        rows.map((char) => ({
          ...char,
          image_path: toPublicPath(char.image_path),
        }))
      );
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Charaktere konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/admin/characters",
  ensureAuthenticated,
  ensureRole("admin"),
  upload.single("image"),
  async (req, res) => {
    const { name } = req.body;
    if (!name?.trim())
      return res.status(400).json({ error: "Charaktername erforderlich" });
    try {
      const imagePath = req.file ? req.file.path : null;
      const { rows } = await pool.query(
        `INSERT INTO characters (name, image_path)
         VALUES ($1, $2) RETURNING id, name, image_path`,
        [name.trim(), imagePath]
      );
      const character = rows[0];
      res.status(201).json({
        ...character,
        image_path: toPublicPath(character.image_path),
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Charakter konnte nicht angelegt werden" });
    }
  }
);

// ----- Level -----
app.get(
  "/api/admin/levels",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, title, xp_threshold FROM levels ORDER BY xp_threshold"
      );
      res.json(
        rows.map((lvl) => ({
          ...lvl,
          xp_threshold: Number(lvl.xp_threshold) || 0,
        }))
      );
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Level konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/admin/levels",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { title, xp_threshold } = req.body;
    if (!title?.trim() || !xp_threshold)
      return res
        .status(400)
        .json({ error: "Titel und XP-Schwelle sind erforderlich" });
    try {
      const { rows } = await pool.query(
        `INSERT INTO levels (title, xp_threshold)
         VALUES ($1, $2) RETURNING id, title, xp_threshold`,
        [title.trim(), Number(xp_threshold)]
      );
      res.status(201).json({
        ...rows[0],
        xp_threshold: Number(rows[0].xp_threshold) || 0,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Level konnte nicht angelegt werden" });
    }
  }
);

// ----- Mission Uploads Verwaltung -----
app.get(
  "/api/admin/mission-uploads",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT u.id, u.file_path, u.created_at, m.title AS mission_title, s.name AS student_name
         FROM student_mission_uploads u
         JOIN missions m ON m.id = u.mission_id
         JOIN users s ON s.id = u.student_id
         ORDER BY u.created_at DESC`
      );
      res.json(
        rows.map((row) => ({
          id: row.id,
          file_path: toPublicPath(row.file_path),
          created_at: row.created_at,
          mission_title: row.mission_title,
          student_name: row.student_name,
        }))
      );
    } catch (error) {
      console.error(error);
      res
        .status(500)
        .json({ error: "Mission-Uploads konnten nicht geladen werden" });
    }
  }
);

app.delete(
  "/api/admin/mission-uploads/:id",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    try {
      const { rows } = await pool.query(
        "DELETE FROM student_mission_uploads WHERE id = $1 RETURNING file_path",
        [id]
      );
      if (!rows[0])
        return res.status(404).json({ error: "Upload nicht gefunden" });
      const filePath = rows[0].file_path;
      if (filePath && fs.existsSync(filePath)) {
        fs.unlink(filePath, () => {});
      }
      res.json({ success: true });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Upload konnte nicht gelöscht werden" });
    }
  }
);

// ----- Schüler:innenseite -----
app.get(
  "/api/student/dashboard",
  ensureAuthenticated,
  ensureRole("student"),
  async (req, res) => {
    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
        req.session.user.id,
      ]);
      const user = rows[0];
      if (!user) return res.status(404).json({ error: "Benutzer nicht gefunden" });

      let traits = Array.isArray(user.traits)
        ? user.traits
        : user.traits
        ? JSON.parse(user.traits)
        : [];
      let equipment = Array.isArray(user.equipment)
        ? user.equipment
        : user.equipment
        ? JSON.parse(user.equipment)
        : [];
      let characterId = user.character_id;

      if (!traits || traits.length === 0) {
        traits = pickRandomItems(CHARACTER_TRAITS, 3);
        await pool.query(
          "UPDATE users SET traits = $1, updated_at = NOW() WHERE id = $2",
          [JSON.stringify(traits), user.id]
        );
      }

      if (!equipment || equipment.length === 0) {
        equipment = pickRandomItems(EQUIPMENT, 3);
        await pool.query(
          "UPDATE users SET equipment = $1, updated_at = NOW() WHERE id = $2",
          [JSON.stringify(equipment), user.id]
        );
      }

      let character = null;
      if (!characterId) {
        const { rows: characterRows } = await pool.query(
          "SELECT id, name, image_path FROM characters ORDER BY RANDOM() LIMIT 1"
        );
        if (characterRows[0]) {
          characterId = characterRows[0].id;
          await pool.query(
            "UPDATE users SET character_id = $1, updated_at = NOW() WHERE id = $2",
            [characterId, user.id]
          );
          character = characterRows[0];
        }
      } else {
        const { rows: characterRows } = await pool.query(
          "SELECT id, name, image_path FROM characters WHERE id = $1",
          [characterId]
        );
        character = characterRows[0] || null;
      }

      const { rows: levels } = await pool.query(
        "SELECT id, title, xp_threshold FROM levels ORDER BY xp_threshold"
      );

      const currentXp = Number(user.xp) || 0;
      const highestXp = Number(user.highest_xp) || 0;
      const levelInfo = determineLevel(levels, highestXp);

      const currentLevel = levelInfo.level
        ? {
            id: levelInfo.level.id ?? 0,
            title: levelInfo.level.title ?? 'Novize',
            xp_threshold: Number(levelInfo.level.xp_threshold ?? 0),
          }
        : { id: 0, title: 'Novize', xp_threshold: 0 };
      const upcomingLevel = levelInfo.nextLevel
        ? {
            id: levelInfo.nextLevel.id ?? 0,
            title: levelInfo.nextLevel.title ?? '',
            xp_threshold: Number(levelInfo.nextLevel.xp_threshold ?? 0),
          }
        : null;

      res.json({
        name: user.name,
        xp: currentXp,
        highestXp,
        traits,
        equipment,
        character: character
          ? {
              id: character.id,
              name: character.name,
              image_path: toPublicPath(character.image_path),
            }
          : null,
        level: currentLevel,
        nextLevel: upcomingLevel,
        levels: levels.map((lvl) => ({
          id: lvl.id,
          title: lvl.title,
          xp_threshold: Number(lvl.xp_threshold) || 0,
        })),
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Dashboard konnte nicht geladen werden" });
    }
  }
);

app.get(
  "/api/student/missions",
  ensureAuthenticated,
  ensureRole("student"),
  async (_req, res) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, title, description, xp_value, image_path, allow_upload FROM missions ORDER BY created_at DESC"
      );
      res.json(
        rows.map((mission) => ({
          ...mission,
          xp_value: Number(mission.xp_value) || 0,
          image_path: toPublicPath(mission.image_path),
        }))
      );
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Missionen konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/student/missions/:id/upload",
  ensureAuthenticated,
  ensureRole("student"),
  upload.single("image"),
  async (req, res) => {
    const { id } = req.params;
    try {
      const { rows } = await pool.query(
        "SELECT allow_upload FROM missions WHERE id = $1",
        [id]
      );
      if (!rows[0] || !rows[0].allow_upload)
        return res
          .status(400)
          .json({ error: "Für diese Mission sind keine Uploads möglich" });
      if (!req.file)
        return res.status(400).json({ error: "Bilddatei erforderlich" });

      const { rows: insertRows } = await pool.query(
        `INSERT INTO student_mission_uploads (mission_id, student_id, file_path)
         VALUES ($1, $2, $3)
         RETURNING id, file_path, created_at`,
        [id, req.session.user.id, req.file.path]
      );
      const uploadEntry = insertRows[0];
      res.status(201).json({
        id: uploadEntry.id,
        file_path: toPublicPath(uploadEntry.file_path),
        created_at: uploadEntry.created_at,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Upload fehlgeschlagen" });
    }
  }
);

app.get(
  "/api/student/bonus-cards",
  ensureAuthenticated,
  ensureRole("student"),
  async (req, res) => {
    try {
      const { rows: userRows } = await pool.query(
        "SELECT xp, highest_xp FROM users WHERE id = $1",
        [req.session.user.id]
      );
      if (!userRows[0])
        return res.status(404).json({ error: "Benutzer nicht gefunden" });
      const currentXp = Number(userRows[0].xp) || 0;
      const highestXp = Number(userRows[0].highest_xp) || 0;

      const { rows } = await pool.query(
        `SELECT id, title, description, xp_cost, image_path FROM bonus_cards ORDER BY xp_cost`
      );
      res.json(
        rows.map((card) => {
          const cost = Number(card.xp_cost) || 0;
          return {
            ...card,
            xp_cost: cost,
            unlocked: highestXp >= cost,
            canRedeem: currentXp >= cost,
            image_path: toPublicPath(card.image_path),
          };
        })
      );
    } catch (error) {
      console.error(error);
      res
        .status(500)
        .json({ error: "Bonuskarten konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/student/bonus-cards/:id/redeem",
  ensureAuthenticated,
  ensureRole("student"),
  async (req, res) => {
    const { id } = req.params;
    try {
      const { rows: cardRows } = await pool.query(
        "SELECT xp_cost FROM bonus_cards WHERE id = $1",
        [id]
      );
      if (!cardRows[0])
        return res.status(404).json({ error: "Bonuskarte nicht gefunden" });
      const cost = Number(cardRows[0].xp_cost) || 0;

      const { rows: userRows } = await pool.query(
        "SELECT xp, highest_xp FROM users WHERE id = $1",
        [req.session.user.id]
      );
      const user = userRows[0];
      if (!user) return res.status(404).json({ error: "Benutzer nicht gefunden" });
      const currentXp = Number(user.xp) || 0;
      const highestXp = Number(user.highest_xp) || 0;

      if (currentXp < cost)
        return res
          .status(400)
          .json({ error: "Nicht genug XP zum Einlösen" });

      const newXp = currentXp - cost;
      await pool.query(
        "UPDATE users SET xp = $1, updated_at = NOW() WHERE id = $2",
        [newXp, req.session.user.id]
      );
      await pool.query(
        `INSERT INTO bonus_redemptions (bonus_card_id, student_id)
         VALUES ($1, $2)`,
        [id, req.session.user.id]
      );
      await pool.query(
        `INSERT INTO xp_transactions (student_id, amount, reason, awarded_by)
         VALUES ($1, $2, $3, $4)`,
        [
          req.session.user.id,
          -cost,
          "Bonuskarte eingelöst",
          req.session.user.id,
        ]
      );
      res.json({ xp: newXp, highestXp });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Bonuskarte konnte nicht eingelöst werden" });
    }
  }
);

function pickRandomItems(source, count) {
  const pool = [...source];
  const result = [];
  while (result.length < count && pool.length) {
    const index = Math.floor(Math.random() * pool.length);
    result.push(pool.splice(index, 1)[0]);
  }
  return result;
}

function determineLevel(levels, highestXp) {
  if (!levels.length)
    return {
      level: { title: "Novize", xp_threshold: 0 },
      nextLevel: null,
    };
  let current = levels[0];
  let next = null;
  for (const lvl of levels) {
    if (highestXp >= Number(lvl.xp_threshold)) {
      current = lvl;
    } else {
      next = lvl;
      break;
    }
  }
  return { level: current, nextLevel: next };
}

initDatabase()
  .then(() => {
    app.listen(PORT, () =>
      console.log(`✅ Server läuft auf Port ${PORT}`)
    );
  })
  .catch((error) => {
    console.error("Fehler beim Initialisieren der Datenbank", error);
    process.exit(1);
  });