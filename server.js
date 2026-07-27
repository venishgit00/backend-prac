const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const OWNER_EMAIL = process.env.OWNER_EMAIL || "owner@cafe.com";
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || "owner123";

if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET environment variable is not set");
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error("FATAL: DATABASE_URL environment variable is not set");
  process.exit(1);
}

const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || "")
  .split(",")
  .map((e) => e.trim().toLowerCase())
  .filter(Boolean);

function isEmailAllowed(email) {
  if (ALLOWED_EMAILS.length === 0) return true;
  return ALLOWED_EMAILS.includes(email.toLowerCase());
}

app.set("trust proxy", 1);

app.use(compression());

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

const cors = require("cors");
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true,
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many attempts, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/api/users/login", authLimiter);
app.use("/api/users/register", authLimiter);
app.use("/api/staff/login", authLimiter);
app.use("/api/owner/login", authLimiter);

app.use(express.json({ limit: "10mb" }));
app.use((req, res, next) => {
  if (req.path.endsWith(".html")) {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  }
  next();
});

app.use(express.static(path.join(__dirname, "public"), {
  maxAge: process.env.NODE_ENV === "production" ? "1y" : 0,
  immutable: true,
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" || process.env.DATABASE_URL?.includes("neon.tech")
    ? { rejectUnauthorized: false }
    : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      phone TEXT DEFAULT '',
      createdAt TEXT NOT NULL,
      token_version INTEGER DEFAULT 0
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      phone TEXT DEFAULT '',
      status TEXT DEFAULT 'pending',
      addedBy INTEGER DEFAULT NULL,
      notified INTEGER DEFAULT 1,
      createdAt TEXT NOT NULL,
      token_version INTEGER DEFAULT 0
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bookings (
      id SERIAL PRIMARY KEY,
      userId INTEGER NOT NULL,
      userName TEXT NOT NULL,
      userEmail TEXT NOT NULL,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      guests INTEGER NOT NULL,
      tableId INTEGER NOT NULL,
      tableLabel TEXT NOT NULL,
      status TEXT DEFAULT 'confirmed',
      createdAt TEXT NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tables (
      id SERIAL PRIMARY KEY,
      capacity INTEGER NOT NULL,
      x REAL NOT NULL,
      y REAL NOT NULL,
      label TEXT NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value INTEGER NOT NULL DEFAULT 0
    )
  `);

  await pool.query(
    "INSERT INTO settings (key, value) VALUES ('owner_token_version', 0) ON CONFLICT (key) DO NOTHING"
  );

  const tableCount = await pool.query("SELECT COUNT(*)::int as count FROM tables");
  if (tableCount.rows[0].count === 0) {
    const seed = [
      [2, 5, 5, "T1"], [2, 25, 5, "T2"], [4, 50, 5, "T3"], [4, 75, 5, "T4"],
      [6, 5, 40, "T5"], [2, 30, 40, "T6"], [4, 55, 40, "T7"],
      [6, 5, 75, "T8"], [4, 35, 75, "T9"], [2, 65, 75, "T10"],
    ];
    for (const row of seed) {
      await pool.query(
        "INSERT INTO tables (capacity, x, y, label) VALUES ($1, $2, $3, $4)", row
      );
    }
  }
}

const DATA_DIR = path.join(__dirname, "data");
const fs = require("fs");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const OFFERS_FILE = path.join(DATA_DIR, "offers.json");
const UPLOADS_DIR = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

function initOffers() {
  if (!fs.existsSync(OFFERS_FILE)) {
    saveOffers({ offers: [
      { slot: 0, image: null, label: "Special Offer 1" },
      { slot: 1, image: null, label: "Special Offer 2" },
      { slot: 2, image: null, label: "Special Offer 3" },
      { slot: 3, image: null, label: "Special Offer 4" },
    ]});
  }
}

function loadOffers() {
  try { return JSON.parse(fs.readFileSync(OFFERS_FILE, "utf8")); } catch { return { offers: [] }; }
}

function saveOffers(data) {
  fs.writeFileSync(OFFERS_FILE, JSON.stringify(data));
}

// ─── HELPERS ───

function parseCookies(req) {
  const cookie = req.headers.cookie;
  if (!cookie) return {};
  const cookies = {};
  cookie.split(";").forEach((c) => {
    const idx = c.indexOf("=");
    if (idx === -1) return;
    const name = c.slice(0, idx).trim();
    const value = c.slice(idx + 1).trim();
    try { cookies[name] = decodeURIComponent(value); } catch { cookies[name] = value; }
  });
  return cookies;
}

function setTokenCookie(req, res, token) {
  const isProd = process.env.NODE_ENV === "production";
  res.cookie("token", token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    maxAge: 365 * 24 * 60 * 60 * 1000,
  });
}

async function getCurrentTokenVersion(role, id) {
  const doQuery = async () => {
    if (role === "owner") {
      const row = await pool.query("SELECT value FROM settings WHERE key = 'owner_token_version'");
      return row.rows[0]?.value || 0;
    }
    const table = role === "user" ? "users" : "staff";
    const row = await pool.query(`SELECT token_version FROM ${table} WHERE id = $1`, [id]);
    return row.rows[0]?.token_version ?? 0;
  };
  try {
    return await doQuery();
  } catch {
    return await doQuery();
  }
}

function authMiddleware(role) {
  return async (req, res, next) => {
    const cookies = parseCookies(req);
    const token = req.headers.authorization?.split(" ")[1] || cookies.token;
    if (!token) return res.status(401).json({ error: "No token provided" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role && decoded.role !== "owner")
        return res.status(403).json({ error: "Access denied" });
      const currentVersion = await getCurrentTokenVersion(decoded.role, decoded.id);
      if ((decoded.token_version || 0) !== currentVersion)
        return res.status(401).json({ error: "Session expired, please login again" });
      req.user = decoded;
      next();
    } catch {
      res.status(401).json({ error: "Invalid token" });
    }
  };
}

// ─── AUTH ROUTES ───

app.post("/api/users/register", async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: "Name, email, password required" });

    if (!isEmailAllowed(email))
      return res.status(403).json({ error: "Registration is restricted to authorized email addresses only" });

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rows[0]) return res.status(400).json({ error: "Email already registered" });
    const staffCheck = await pool.query("SELECT id FROM staff WHERE email = $1", [email]);
    if (staffCheck.rows[0]) return res.status(400).json({ error: "This email belongs to a staff account." });

    const hashed = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();
    const result = await pool.query(
      "INSERT INTO users (name, email, password, phone, createdAt) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [name, email, hashed, phone || "", createdAt]
    );
    const id = result.rows[0].id;

    const token = jwt.sign(
      { id, email, name, role: "user", token_version: 0 },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    setTokenCookie(req, res, token);
    res.json({ token, user: { id, name, email, role: "user" } });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/users/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const staffCheck = await pool.query("SELECT id FROM staff WHERE email = $1", [email]);
    if (staffCheck.rows[0]) return res.status(401).json({ error: "This email belongs to a staff account. Please use the staff login." });
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!user.rows[0])
      return res.status(401).json({ error: "Email id not available" });
    if (!(await bcrypt.compare(password, user.rows[0].password)))
      return res.status(401).json({ error: "Incorrect password" });

    const token = jwt.sign(
      { id: user.rows[0].id, email: user.rows[0].email, name: user.rows[0].name, role: "user", token_version: user.rows[0].token_version || 0 },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    setTokenCookie(req, res, token);
    res.json({ token, user: { id: user.rows[0].id, name: user.rows[0].name, email: user.rows[0].email, role: "user" } });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/staff/register", authMiddleware("owner"), async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: "Name, email, password required" });
    if (phone && !/^\d{10}$/.test(phone))
      return res.status(400).json({ error: "Phone number must be exactly 10 digits" });

    const existing = await pool.query("SELECT id FROM staff WHERE email = $1", [email]);
    if (existing.rows[0]) return res.status(400).json({ error: "Email already exists" });
    const userCheck = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (userCheck.rows[0]) return res.status(400).json({ error: "This email belongs to a customer account." });

    const hashed = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();
    const result = await pool.query(
      "INSERT INTO staff (name, email, password, phone, status, addedBy, createdAt) VALUES ($1, $2, $3, $4, 'approved', $5, $6) RETURNING id",
      [name, email, hashed, phone || "", req.user.id, createdAt]
    );

    res.json({ staff: { id: result.rows[0].id, name, email, status: "approved" } });
  } catch (e) {
    console.error("Error registering staff:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/staff/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const userCheck = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (userCheck.rows[0]) return res.status(401).json({ error: "This email belongs to a customer account. Please use the customer login." });
    const staff = await pool.query("SELECT * FROM staff WHERE email = $1", [email]);
    if (!staff.rows[0])
      return res.status(401).json({ error: "Email id not available" });
    if (!(await bcrypt.compare(password, staff.rows[0].password)))
      return res.status(401).json({ error: "Incorrect password" });

    const s = staff.rows[0];
    if (s.status === "pending")
      return res.status(403).json({ error: "Your account is pending owner approval", pending: true });
    if (s.status === "rejected")
      return res.status(403).json({ error: "Owner has rejected your request." });
    if (s.status === "removed")
      return res.status(403).json({ error: "Your access has been revoked by the owner." });

    const showApproval = s.notified === 0;
    if (s.notified === 0) {
      await pool.query("UPDATE staff SET notified = 1 WHERE id = $1", [s.id]);
    }

    const token = jwt.sign(
      { id: s.id, email: s.email, name: s.name, role: "staff", token_version: s.token_version || 0 },
      JWT_SECRET,
      { expiresIn: "100y" }
    );
    setTokenCookie(req, res, token);
    res.json({ token, user: { id: s.id, name: s.name, email: s.email, role: "staff" }, showApproval });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/staff/request", async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: "Name, email, password required" });

    const existing = await pool.query("SELECT id FROM staff WHERE email = $1", [email]);
    if (existing.rows[0]) return res.status(400).json({ error: "Email already exists" });
    const userCheck = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (userCheck.rows[0]) return res.status(400).json({ error: "This email belongs to a customer account. Please use the customer registration." });

    const hashed = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();
    const result = await pool.query(
      "INSERT INTO staff (name, email, password, phone, status, createdAt) VALUES ($1, $2, $3, $4, 'pending', $5) RETURNING id",
      [name, email, hashed, phone || "", createdAt]
    );

    res.json({
      message: "Registration request sent. Waiting for owner approval.",
      staff: { id: result.rows[0].id, name, email, status: "pending" },
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/owner/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (email !== OWNER_EMAIL)
      return res.status(401).json({ error: "Email id not available" });
    if (password !== OWNER_PASSWORD)
      return res.status(401).json({ error: "Incorrect password" });

    const row = await pool.query("SELECT value FROM settings WHERE key = 'owner_token_version'");
    const currentVersion = row.rows[0]?.value || 0;
    const token = jwt.sign(
      { id: 0, email: OWNER_EMAIL, name: "Owner", role: "owner", token_version: currentVersion },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    setTokenCookie(req, res, token);
    res.json({ token, user: { id: 0, name: "Owner", email: OWNER_EMAIL, role: "owner" } });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ─── SESSION RESTORE ───

app.get("/api/auth/me", async (req, res) => {
  const cookies = parseCookies(req);
  const token = req.headers.authorization?.split(" ")[1] || cookies.token;
  if (!token) return res.json({ user: null });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentVersion = await getCurrentTokenVersion(decoded.role, decoded.id);
    if ((decoded.token_version || 0) !== currentVersion) {
      if (decoded.role === "staff") {
        const staff = await pool.query("SELECT status, name, email FROM staff WHERE id = $1", [decoded.id]);
        if (!staff.rows[0] || staff.rows[0].status !== "approved")
          return res.json({ user: null, removed: true });
        // Staff is still approved - issue new token with current version
        const newToken = jwt.sign(
          { id: decoded.id, email: staff.rows[0].email, name: staff.rows[0].name, role: "staff", token_version: currentVersion },
          JWT_SECRET,
          { expiresIn: "100y" }
        );
        setTokenCookie(req, res, newToken);
        return res.json({
          user: { id: decoded.id, name: staff.rows[0].name, email: staff.rows[0].email, role: "staff" },
          token: newToken,
        });
      } else {
        return res.json({ user: null });
      }
    }
    const newToken = jwt.sign(
      { id: decoded.id, email: decoded.email, name: decoded.name, role: decoded.role, token_version: currentVersion },
      JWT_SECRET,
      { expiresIn: decoded.role === "staff" ? "100y" : "30d" }
    );
    setTokenCookie(req, res, newToken);
    res.json({
      user: { id: decoded.id, name: decoded.name, email: decoded.email, role: decoded.role },
      token: newToken,
    });
  } catch {
    res.json({ user: null });
  }
});

// ─── LOGOUT ───

app.post("/api/logout", async (req, res) => {
  const cookies = parseCookies(req);
  const token = req.headers.authorization?.split(" ")[1] || cookies.token;
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role === "owner") {
      await pool.query("UPDATE settings SET value = value + 1 WHERE key = 'owner_token_version'");
    } else {
      const table = decoded.role === "user" ? "users" : "staff";
      await pool.query(`UPDATE ${table} SET token_version = token_version + 1 WHERE id = $1`, [decoded.id]);
    }
    res.clearCookie("token");
    res.json({ message: "Logged out successfully" });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

// ─── STAFF MANAGEMENT ───

app.get("/api/staff/pending", authMiddleware("owner"), async (req, res) => {
  const rows = await pool.query(`SELECT id, name, email, phone, status, createdat AS "createdAt" FROM staff WHERE status = 'pending'`);
  res.json(rows.rows);
});

app.get("/api/staff/all", authMiddleware("owner"), async (req, res) => {
  const rows = await pool.query(`SELECT id, name, email, phone, status, createdat AS "createdAt" FROM staff`);
  res.json(rows.rows);
});

app.post("/api/staff/approve", authMiddleware("owner"), async (req, res) => {
  try {
    const { staffId } = req.body;
    const result = await pool.query(
      "UPDATE staff SET status = 'approved', notified = 0, token_version = token_version + 1 WHERE id = $1",
      [staffId]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "Staff not found" });
    const staff = await pool.query("SELECT id, name, email, status FROM staff WHERE id = $1", [staffId]);
    res.json({ message: "Staff approved", staff: staff.rows[0] });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/staff/reject", authMiddleware("owner"), async (req, res) => {
  try {
    const { staffId } = req.body;
    const result = await pool.query(
      "UPDATE staff SET status = 'rejected', token_version = token_version + 1 WHERE id = $1",
      [staffId]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "Staff not found" });
    res.json({ message: "Staff rejected" });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/staff/remove", authMiddleware("owner"), async (req, res) => {
  try {
    const { staffId } = req.body;
    const result = await pool.query(
      "UPDATE staff SET status = 'removed', token_version = token_version + 1 WHERE id = $1",
      [staffId]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "Staff not found" });
    res.json({ message: "Staff removed successfully" });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ─── BOOKINGS ───

app.post("/api/bookings/create", authMiddleware("user"), async (req, res) => {
  try {
    const { date, time, guests, tableId } = req.body;
    if (!date || !time || !guests || !tableId)
      return res.status(400).json({ error: "All fields required" });

    const table = await pool.query("SELECT * FROM tables WHERE id = $1", [tableId]);
    if (!table.rows[0]) return res.status(400).json({ error: "Invalid table" });
    if (guests > table.rows[0].capacity)
      return res.status(400).json({ error: `Table capacity is ${table.rows[0].capacity} guests` });

    const conflict = await pool.query(
      "SELECT id FROM bookings WHERE tableId = $1 AND date = $2 AND time = $3 AND status = 'confirmed'",
      [tableId, date, time]
    );
    if (conflict.rows[0])
      return res.status(400).json({ error: "Table already booked for this time slot" });

    const createdAt = new Date().toISOString();
    const result = await pool.query(
      `INSERT INTO bookings (userId, userName, userEmail, date, time, guests, tableId, tableLabel, status, createdAt) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'confirmed', $9) RETURNING id, userid AS "userId", username AS "userName", useremail AS "userEmail", date, time, guests, tableid AS "tableId", tablelabel AS "tableLabel", status, createdat AS "createdAt"`,
      [req.user.id, req.user.name, req.user.email, date, time, guests, tableId, table.rows[0].label, createdAt]
    );

    res.json({ booking: result.rows[0] });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/tables/available", async (req, res) => {
  const { date, time, guests } = req.query;
  const allTables = await pool.query("SELECT * FROM tables");

  const bookedRows = await pool.query(
    "SELECT tableId FROM bookings WHERE date = $1 AND time = $2 AND status = 'confirmed'",
    [date, time]
  );
  const bookedIds = bookedRows.rows.map((r) => r.tableid);

  const available = allTables.rows.filter((t) => !bookedIds.includes(t.id));
  const filtered = guests ? available.filter((t) => t.capacity >= parseInt(guests)) : available;
  const booked = allTables.rows.filter((t) => bookedIds.includes(t.id));

  res.json({ available: filtered, booked, all: allTables.rows });
});

app.get("/api/bookings/my", authMiddleware("user"), async (req, res) => {
  const rows = await pool.query(`SELECT id, userid AS "userId", username AS "userName", useremail AS "userEmail", date, time, guests, tableid AS "tableId", tablelabel AS "tableLabel", status, createdat AS "createdAt" FROM bookings WHERE userid = $1`, [req.user.id]);
  res.json(rows.rows);
});

app.post("/api/bookings/cancel", authMiddleware("user"), async (req, res) => {
  try {
    const { bookingId } = req.body;
    const booking = await pool.query("SELECT * FROM bookings WHERE id = $1 AND userId = $2", [bookingId, req.user.id]);
    if (!booking.rows[0]) return res.status(404).json({ error: "Booking not found" });
    if (booking.rows[0].status !== "confirmed") return res.status(400).json({ error: "Booking is already cancelled" });

    const today = new Date().toISOString().split("T")[0];
    const isSameDay = booking.rows[0].date === today;

    await pool.query("UPDATE bookings SET status = 'cancelled' WHERE id = $1", [bookingId]);
    res.json({
      message: isSameDay
        ? "Booking cancelled. 20% refund will be processed (80% cancellation charge applies for same-day cancellations)."
        : "Booking cancelled successfully.",
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ─── OFFERS MANAGEMENT ───

initOffers();

app.get("/api/offers", (req, res) => {
  res.json(loadOffers());
});

app.post("/api/offers/update", authMiddleware("owner"), (req, res) => {
  try {
    const { slot, image, label } = req.body;
    const data = loadOffers();
    const offer = data.offers.find((o) => o.slot === slot);
    if (!offer) return res.status(404).json({ error: "Offer slot not found" });

    if (label !== undefined) offer.label = label;

    if (image) {
      const matches = image.match(/^data:image\/(\w+);base64,(.+)$/);
      if (!matches) return res.status(400).json({ error: "Invalid image data" });
      const ext = matches[1] === "jpeg" ? "jpg" : matches[1];
      const buffer = Buffer.from(matches[2], "base64");
      const filename = `offer-${slot}.${ext}`;
      fs.writeFileSync(path.join(UPLOADS_DIR, filename), buffer);
      if (offer.image && offer.image !== `/uploads/${filename}`) {
        const oldPath = path.join(__dirname, "public", offer.image);
        try { fs.unlinkSync(oldPath); } catch {}
      }
      offer.image = `/uploads/${filename}`;
    }

    saveOffers(data);
    res.json({ message: "Offer updated", offers: data.offers });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/offers/remove-image", authMiddleware("owner"), (req, res) => {
  try {
    const { slot } = req.body;
    const data = loadOffers();
    const offer = data.offers.find((o) => o.slot === slot);
    if (!offer) return res.status(404).json({ error: "Offer slot not found" });
    if (offer.image) {
      const oldPath = path.join(__dirname, "public", offer.image);
      try { fs.unlinkSync(oldPath); } catch {}
    }
    offer.image = null;
    saveOffers(data);
    res.json({ message: "Image removed", offers: data.offers });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ─── STAFF DASHBOARD ───

app.get("/api/users/all", authMiddleware("staff"), async (req, res) => {
  const rows = await pool.query(`SELECT id, name, email, phone, createdat AS "createdAt" FROM users`);
  res.json(rows.rows);
});

app.get("/api/bookings/all", authMiddleware("staff"), async (req, res) => {
  const rows = await pool.query(`SELECT id, userid AS "userId", username AS "userName", useremail AS "userEmail", date, time, guests, tableid AS "tableId", tablelabel AS "tableLabel", status, createdat AS "createdAt" FROM bookings`);
  res.json(rows.rows);
});

// ─── START ───

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Cafe Management Server running on http://localhost:${PORT}`);
    console.log(`Owner login: ${OWNER_EMAIL} / ${OWNER_PASSWORD.replace(/./g, "*")}`);
  });
}).catch((e) => {
  console.error("Database initialization failed:", e);
  process.exit(1);
});
