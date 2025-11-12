// index.js
// Dies ist der Startpunkt Ihres Temple of Logic Backend-Servers

// 1. Benötigte Werkzeuge holen
const express = require('express');
const mongoose = require('mongoose'); // Werkzeug für die Kommunikation mit MongoDB

// 2. Die Anwendung starten
const app = express();

// 3. Wichtige Konfigurationen (Schlüssel und Türen)
// Port: Nimm, was Railway (process.env.PORT) vorgibt, oder 3000 für lokales Testen.
const PORT = process.env.PORT || 3000; 
// MONGO_URL: Holt den Datenbank-Schlüssel, den Railway bereitstellt.
const MONGO_URL = process.env.MONGO_URL; 

// Middleware (Küchenhelfer):
// Erlaubt dem Server, JSON-Daten im Body von Anfragen zu lesen (z.B. beim Login).
app.use(express.json()); 

// 4. Funktion zur Verbindung mit der Datenbank (Lagerraum)
const connectDB = async () => {
    // Sicherheitsprüfung: Ist der Schlüssel vorhanden?
    if (!MONGO_URL) {
        console.error("🔴 Fehler: MONGO_URL wurde nicht gefunden. Kann keine Verbindung zur Datenbank herstellen!");
        // Wenn kein Schlüssel da ist, beende den Prozess, damit Railway weiß, dass es einen Fehler gibt.
        process.exit(1); 
    }
    
    try {
        // Versuche, eine Verbindung zur MongoDB herzustellen
        await mongoose.connect(MONGO_URL);
        console.log('📦 Datenbank (Lagerraum) erfolgreich verbunden!');
    } catch (error) {
        console.error('❌ Fehler bei der Datenbankverbindung:', error.message);
        // Beende die App bei Fehler
        process.exit(1); 
    }
};

// 5. Die Haupt-Route
app.get('/', (req, res) => {
    // res.send schickt die Antwort zum Browser
    res.send('Willkommen beim Temple of Logic API! Die Küche ist offen und bereit für XP-Vergabe.');
});


// **********************************************
// * ZUKÜNFTIGE API-ROUTEN WERDEN HIER EINGEBUNDEN:
// * app.use('/api/auth', require('./routes/auth'));
// * app.use('/api/xp', require('./routes/xp'));
// **********************************************


// 6. Server starten: Zuerst DB verbinden, dann auf Anfragen warten (listen)
connectDB().then(() => {
    // Nur starten, wenn die DB-Verbindung erfolgreich war
    app.listen(PORT, () => {
        console.log(`✅ Server (die Küche) läuft auf Port ${PORT}.`);
    });
});