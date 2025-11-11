import sqlite3 from "sqlite3";
import pg from "pg";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

const db = new sqlite3.Database("temple.db");

db.serialize(async () => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE,
      password TEXT,
      role TEXT,
      class_id INTEGER
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS classes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT
    )
  `);

  const hash = await bcrypt.hash("admin", 10);
  db.run("INSERT OR IGNORE INTO users (name, password, role) VALUES (?, ?, ?)", ["admin", hash, "admin"]);

  console.log("✅ Datenbank initialisiert, Admin-Login: admin / admin");
  db.close();
dotenv.config();

const { Pool } = pg;
const connectionString =
  process.env.DATABASE_URL ||
  "postgresql://postgres:postgres@localhost:5432/temple_of_logic";

const pool = new Pool({
  connectionString,
  ssl:
    connectionString.includes("railway") || process.env.PGSSLMODE === "require"
      ? { rejectUnauthorized: false }
      : false,
});

async function run() {
  try {
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

    console.log("✅ Datenbanktabellen erstellt. Admin-Login: admin / admin");
  } catch (error) {
    console.error("❌ Fehler beim Initialisieren der Datenbank", error);
  } finally {
    await pool.end();
  }
}

run();