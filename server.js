require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const mysql = require("mysql2/promise");

const app = express();

// --- MySQL pool ---
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
});

// --- Middleware-ek ---
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// --- Multer beállítás (lokális fájltárolás) ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, "uploads/");
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + "-" + uniqueSuffix + ext);
    },
});
const upload = multer({ storage });

// --- Auth middleware ---
function authRequired(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader)
        return res.status(401).json({ error: "Hiányzó Authorization header" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Hiányzó token" });

    jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
        if (err) return res.status(401).json({ error: "Érvénytelen token" });
        req.userId = payload.userId;
        next();
    });
}

// --- Auth endpointok ---

// Regisztráció
app.post("/auth/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password)
            return res
                .status(400)
                .json({ error: "username, email, password kötelező" });

        const [existing] = await pool.query(
            "SELECT id FROM users WHERE email = ? OR username = ?",
            [email, username]
        );
        if (existing.length > 0) {
            return res
                .status(409)
                .json({ error: "A felhasználó már létezik (email vagy username foglalt)" });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const [result] = await pool.query(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            [username, email, passwordHash]
        );

        const userId = result.insertId;

        res.status(201).json({
            id: userId,
            username,
            email,
            createdAt: new Date(), // egyszerűen mostani idő
        });
    } catch (err) {
        console.error("Register error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// Login
app.post("/auth/login", async (req, res) => {
    try {
        const { emailOrUsername, password } = req.body;

        if (!emailOrUsername || !password)
            return res
                .status(400)
                .json({ error: "emailOrUsername és password kötelező" });

        const [rows] = await pool.query(
            "SELECT id, username, email, password_hash FROM users WHERE email = ? OR username = ? LIMIT 1",
            [emailOrUsername, emailOrUsername]
        );

        if (rows.length === 0)
            return res.status(401).json({ error: "Hibás belépési adatok" });

        const user = rows[0];

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) return res.status(401).json({ error: "Hibás belépési adatok" });

        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
            },
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// --- Photo endpointok ---

// Fotó feltöltése (auth + fájl)
app.post("/photos", authRequired, upload.single("image"), async (req, res) => {
    try {
        if (!req.file)
            return res.status(400).json({ error: "Hiányzó image fájl" });

        const { caption } = req.body;
        const fileUrl = `/uploads/${req.file.filename}`;

        const [result] = await pool.query(
            "INSERT INTO photos (owner_id, url, caption) VALUES (?, ?, ?)",
            [req.userId, fileUrl, caption || null]
        );

        const photoId = result.insertId;

        const [rows] = await pool.query(
            "SELECT id, owner_id AS ownerId, url, caption, created_at AS createdAt FROM photos WHERE id = ?",
            [photoId]
        );

        res.status(201).json(rows[0]);
    } catch (err) {
        console.error("Upload photo error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// Fotók listázása (publikus)
app.get("/photos", async (req, res) => {
    try {
        const page = parseInt(req.query.page || "1", 10);
        const limit = parseInt(req.query.limit || "10", 10);
        const offset = (page - 1) * limit;

        const [items] = await pool.query(
            `SELECT 
         p.id,
         p.url,
         p.caption,
         p.created_at AS createdAt,
         u.id AS ownerId,
         u.username AS ownerUsername,
         u.email AS ownerEmail,
         (SELECT COUNT(*) FROM photo_likes pl WHERE pl.photo_id = p.id) AS likesCount
       FROM photos p
       JOIN users u ON u.id = p.owner_id
       ORDER BY p.created_at DESC
       LIMIT ? OFFSET ?`,
            [limit, offset]
        );

        const [countRows] = await pool.query(
            "SELECT COUNT(*) AS total FROM photos"
        );
        const total = countRows[0].total;

        res.json({
            page,
            limit,
            total,
            items,
        });
    } catch (err) {
        console.error("List photos error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// Egy fotó lekérése
app.get("/photos/:id", async (req, res) => {
    try {
        const photoId = req.params.id;

        const [rows] = await pool.query(
            `SELECT 
         p.id,
         p.url,
         p.caption,
         p.created_at AS createdAt,
         u.id AS ownerId,
         u.username AS ownerUsername,
         u.email AS ownerEmail
       FROM photos p
       JOIN users u ON u.id = p.owner_id
       WHERE p.id = ?`,
            [photoId]
        );

        if (rows.length === 0)
            return res.status(404).json({ error: "Fotó nem található" });

        res.json(rows[0]);
    } catch (err) {
        console.error("Get photo error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// Fotó like-olása
app.post("/photos/:id/like", authRequired, async (req, res) => {
    try {
        const photoId = req.params.id;

        // Ellenőrizzük, hogy létezik-e a fotó
        const [photoRows] = await pool.query(
            "SELECT id FROM photos WHERE id = ?",
            [photoId]
        );
        if (photoRows.length === 0)
            return res.status(404).json({ error: "Fotó nem található" });

        // INSERT IGNORE -> ha már létezik (unique (photo_id,user_id)), nem dob hibát
        await pool.query(
            "INSERT IGNORE INTO photo_likes (photo_id, user_id) VALUES (?, ?)",
            [photoId, req.userId]
        );

        const [countRows] = await pool.query(
            "SELECT COUNT(*) AS likesCount FROM photo_likes WHERE photo_id = ?",
            [photoId]
        );

        res.json({ likesCount: countRows[0].likesCount });
    } catch (err) {
        console.error("Like photo error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// Fotó unlike-olása
app.delete("/photos/:id/like", authRequired, async (req, res) => {
    try {
        const photoId = req.params.id;

        await pool.query(
            "DELETE FROM photo_likes WHERE photo_id = ? AND user_id = ?",
            [photoId, req.userId]
        );

        const [countRows] = await pool.query(
            "SELECT COUNT(*) AS likesCount FROM photo_likes WHERE photo_id = ?",
            [photoId]
        );

        res.json({ likesCount: countRows[0].likesCount });
    } catch (err) {
        console.error("Unlike photo error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// --- Komment endpointok ---

// Komment létrehozása egy fotóhoz
app.post("/photos/:id/comments", authRequired, async (req, res) => {
    try {
        const photoId = req.params.id;
        const { text } = req.body;

        if (!text) return res.status(400).json({ error: "text kötelező" });

        const [photoRows] = await pool.query(
            "SELECT id FROM photos WHERE id = ?",
            [photoId]
        );
        if (photoRows.length === 0)
            return res.status(404).json({ error: "Fotó nem található" });

        const [result] = await pool.query(
            "INSERT INTO comments (photo_id, author_id, text) VALUES (?, ?, ?)",
            [photoId, req.userId, text]
        );

        const commentId = result.insertId;

        const [rows] = await pool.query(
            `SELECT 
         c.id,
         c.text,
         c.created_at AS createdAt,
         u.id AS authorId,
         u.username AS authorUsername,
         u.email AS authorEmail
       FROM comments c
       JOIN users u ON u.id = c.author_id
       WHERE c.id = ?`,
            [commentId]
        );

        res.status(201).json(rows[0]);
    } catch (err) {
        console.error("Create comment error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// Kommentek listázása egy fotóhoz
app.get("/photos/:id/comments", async (req, res) => {
    try {
        const photoId = req.params.id;

        const [rows] = await pool.query(
            `SELECT 
         c.id,
         c.text,
         c.created_at AS createdAt,
         u.id AS authorId,
         u.username AS authorUsername,
         u.email AS authorEmail
       FROM comments c
       JOIN users u ON u.id = c.author_id
       WHERE c.photo_id = ?
       ORDER BY c.created_at ASC`,
            [photoId]
        );

        res.json(rows);
    } catch (err) {
        console.error("List comments error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// --- Health check ---
app.get("/", (req, res) => {
    res.json({ status: "ok", message: "Photoshare API (MySQL) fut" });
});

// --- Szerver indítása ---
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
