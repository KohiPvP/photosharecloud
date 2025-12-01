require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const cors = require("cors");

const app = express();

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

// --- MongoDB csatlakozás ---
mongoose
    .connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.error("MongoDB error:", err));

// --- Mongoose sémák / modellek ---

const userSchema = new mongoose.Schema(
    {
        username: { type: String, required: true, unique: true },
        email: { type: String, required: true, unique: true },
        passwordHash: { type: String, required: true },
    },
    { timestamps: true }
);

const photoSchema = new mongoose.Schema(
    {
        owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
        url: { type: String, required: true },
        caption: { type: String },
        likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    },
    { timestamps: true }
);

const commentSchema = new mongoose.Schema(
    {
        photo: { type: mongoose.Schema.Types.ObjectId, ref: "Photo", required: true },
        author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
        text: { type: String, required: true },
    },
    { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Photo = mongoose.model("Photo", photoSchema);
const Comment = mongoose.model("Comment", commentSchema);

// --- Auth middleware ---

function authRequired(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Hiányzó Authorization header" });

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
            return res.status(400).json({ error: "username, email, password kötelező" });

        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(409).json({ error: "A felhasználó már létezik (email vagy username foglalt)" });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const user = await User.create({ username, email, passwordHash });

        res.status(201).json({
            id: user._id,
            username: user.username,
            email: user.email,
            createdAt: user.createdAt,
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
            return res.status(400).json({ error: "emailOrUsername és password kötelező" });

        const user = await User.findOne({
            $or: [{ email: emailOrUsername }, { username: emailOrUsername }],
        });

        if (!user) return res.status(401).json({ error: "Hibás belépési adatok" });

        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(401).json({ error: "Hibás belépési adatok" });

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });

        res.json({
            token,
            user: {
                id: user._id,
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
        if (!req.file) return res.status(400).json({ error: "Hiányzó image fájl" });

        const { caption } = req.body;
        const fileUrl = `/uploads/${req.file.filename}`; // publikus URL

        const photo = await Photo.create({
            owner: req.userId,
            url: fileUrl,
            caption,
        });

        res.status(201).json(photo);
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
        const skip = (page - 1) * limit;

        const [items, total] = await Promise.all([
            Photo.find({})
                .populate("owner", "username email")
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit),
            Photo.countDocuments(),
        ]);

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
        const photo = await Photo.findById(req.params.id).populate("owner", "username email");
        if (!photo) return res.status(404).json({ error: "Fotó nem található" });
        res.json(photo);
    } catch (err) {
        console.error("Get photo error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// Fotó like-olása
app.post("/photos/:id/like", authRequired, async (req, res) => {
    try {
        const photo = await Photo.findById(req.params.id);
        if (!photo) return res.status(404).json({ error: "Fotó nem található" });

        const hasLiked = photo.likes.some(
            (userId) => userId.toString() === req.userId
        );
        if (!hasLiked) {
            photo.likes.push(req.userId);
            await photo.save();
        }

        res.json({ likesCount: photo.likes.length });
    } catch (err) {
        console.error("Like photo error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// Fotó unlike-olása
app.delete("/photos/:id/like", authRequired, async (req, res) => {
    try {
        const photo = await Photo.findById(req.params.id);
        if (!photo) return res.status(404).json({ error: "Fotó nem található" });

        photo.likes = photo.likes.filter(
            (userId) => userId.toString() !== req.userId
        );
        await photo.save();

        res.json({ likesCount: photo.likes.length });
    } catch (err) {
        console.error("Unlike photo error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// --- Komment endpointok ---

// Komment létrehozása egy fotóhoz
app.post("/photos/:id/comments", authRequired, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text) return res.status(400).json({ error: "text kötelező" });

        const photo = await Photo.findById(req.params.id);
        if (!photo) return res.status(404).json({ error: "Fotó nem található" });

        const comment = await Comment.create({
            photo: photo._id,
            author: req.userId,
            text,
        });

        res.status(201).json(comment);
    } catch (err) {
        console.error("Create comment error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// Kommentek listázása egy fotóhoz
app.get("/photos/:id/comments", async (req, res) => {
    try {
        const comments = await Comment.find({ photo: req.params.id })
            .populate("author", "username email")
            .sort({ createdAt: 1 });

        res.json(comments);
    } catch (err) {
        console.error("List comments error:", err);
        res.status(500).json({ error: "Szerver hiba" });
    }
});

// --- Health check ---
app.get("/", (req, res) => {
    res.json({ status: "ok", message: "Photoshare API fut" });
});

// --- Szerver indítása ---
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
