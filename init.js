import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";

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
});
