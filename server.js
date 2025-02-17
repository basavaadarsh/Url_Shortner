const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const shortid = require("shortid");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true })); // Secure CORS

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => console.error("❌ MongoDB Error:", err));

// Define User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});

const User = mongoose.model("User", userSchema);

// Define URL Schema
const urlSchema = new mongoose.Schema({
    shortId: { type: String, unique: true, default: shortid.generate },
    longUrl: { type: String, required: true },
    clicks: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    analytics: [{ timestamp: Date, ip: String, userAgent: String }],
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});
urlSchema.index({ shortId: 1 });
const URL = mongoose.model("URL", urlSchema);

// Middleware for Authentication
const authMiddleware = (req, res, next) => {
    const token = req.header("Authorization");

    if (!token) {
        return res.status(401).json({ message: "Access Denied. No token provided." });
    }

    try {
        const tokenValue = token.split(" ")[1]; // Remove "Bearer " prefix
        const verified = jwt.verify(tokenValue, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid Token" });
    }
};

// User Signup
app.post("/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: "Username, Email, and Password are required" });
        }

        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ message: "Email or Username already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();

        res.json({ message: "User created successfully" });
    } catch (err) {
        console.error("❌ Signup Error:", err);
        res.status(500).json({ message: "Server Error", error: err.message });
    }
});


// User Login
app.post("/login", async (req, res) => {
    try {
        const { usernameOrEmail, password } = req.body;

        const user = await User.findOne({
            $or: [{ email: usernameOrEmail }, { username: usernameOrEmail }]
        });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, username: user.username });
    } catch (err) {
        res.status(500).json({ message: "Server Error" });
    }
});

// URL Shortening
app.post("/shorten", authMiddleware, async (req, res) => {
    try {
        console.log("🟢 Shorten API Called with Data:", req.body);

        const { longUrl, customId } = req.body;
        const userId = req.user._id;

        if (!longUrl) {
            console.log("❌ Error: Long URL is required");
            return res.status(400).json({ message: "Long URL is required" });
        }

        let shortId = customId || shortid.generate();
        const existing = await URL.findOne({ shortId });

        if (existing) {
            console.log("❌ Error: Short ID already taken");
            return res.status(400).json({ message: "Short ID already taken" });
        }

        console.log("🔵 Creating new short URL...");
        const newUrl = new URL({ longUrl, shortId, userId });
        await newUrl.save();

        console.log("✅ Short URL Created:", `${process.env.BASE_URL}/redirect/${shortId}`);
        res.json({ shortUrl: `${process.env.BASE_URL}/redirect/${shortId}` });

    } catch (err) {
        console.error("❌ Error shortening URL:", err);
        res.status(500).json({ message: "Server Error", error: err.message });
    }
});


// URL Redirection
app.get("/redirect/:shortId", async (req, res) => {
    try {
        const url = await URL.findOne({ shortId: req.params.shortId });
        if (!url) return res.status(404).json({ message: "URL not found" });

        url.clicks++;
        url.analytics.push({
            timestamp: new Date(),
            ip: req.ip,
            userAgent: req.headers["user-agent"]
        });
        await url.save();

        res.redirect(url.longUrl);
    } catch (err) {
        res.status(500).json({ message: "Server Error" });
    }
});

// my urls
app.get("/my-urls", authMiddleware, async (req, res) => {
    try {
        console.log("🟢 Fetching URLs for User:", req.user?._id);

        const urls = await URL.find({ userId: req.user._id });

        if (urls.length === 0) {
            return res.json({ message: "No URLs found." });
        }

        res.json(urls);
    } catch (err) {
        console.error("❌ Error fetching URLs:", err);
        res.status(500).json({ message: "Server Error", error: err.message });
    }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
