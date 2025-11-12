// index.js

// 1. Hole das Express-Werkzeug
const express = require('express');

// 2. Erstelle unsere App (unser Restaurant)
const app = express();

// 3. Wähle die Türnummer (Port): Nimm, was Railway (process.env.PORT) vorgibt,
//    oder nimm 3000, wenn wir lokal auf unserem PC testen.
const PORT = process.env.PORT || 3000; 

// Middleware (wichtige Küchenhelfer):
// Erlaubt dem Server, JSON-Daten im Body von Anfragen zu lesen (z.B. beim Login).
app.use(express.json()); 


// Haupt-Route: Der erste Willkommens-Endpunkt
app.get('/', (req, res) => {
    // res.send sendet die Antwort zurück zum Browser
    res.send('Willkommen beim Temple of Logic API! Die Küche ist offen und bereit für XP-Vergabe.');
});


// **********************************************
// * ZUKÜNFTIGE API-ROUTEN HIER EINFÜGEN:
// * app.use('/api/auth', require('./routes/auth'));
// * app.use('/api/xp', require('./routes/xp'));
// **********************************************


// Starte das Zuhören! Der Haupt-Koch hört auf dem zugewiesenen Port zu.
app.listen(PORT, () => {
    console.log(`✅ Server (die Küche) läuft auf Port ${PORT}.`);
    console.log(`   (Online-URL wird von Railway bereitgestellt)`);
});