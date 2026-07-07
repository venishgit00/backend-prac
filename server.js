const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "cafe-management-secret-key-2024";

app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

const DATA_DIR = path.join(__dirname, "data");
if (!require("fs").existsSync(DATA_DIR)) require("fs").mkdirSync(DATA_DIR);
const DB_PATH = path.join(DATA_DIR, "database.sqlite");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      phone TEXT DEFAULT '',
      createdAt TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS staff (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      phone TEXT DEFAULT '',
      status TEXT DEFAULT 'pending',
      addedBy INTEGER DEFAULT NULL,
      notified INTEGER DEFAULT 1,
      createdAt TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    );
    CREATE TABLE IF NOT EXISTS tables (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      capacity INTEGER NOT NULL,
      x REAL NOT NULL,
      y REAL NOT NULL,
      label TEXT NOT NULL
    );
  `);

  const tableCount = db.prepare("SELECT COUNT(*) as count FROM tables").get();
  if (tableCount.count === 0) {
    const insert = db.prepare("INSERT INTO tables (capacity, x, y, label) VALUES (?, ?, ?, ?)");
    const seed = [
      [2, 5, 5, "T1"], [2, 25, 5, "T2"], [4, 50, 5, "T3"], [4, 75, 5, "T4"],
      [6, 5, 40, "T5"], [2, 30, 40, "T6"], [4, 55, 40, "T7"],
      [6, 5, 75, "T8"], [4, 35, 75, "T9"], [2, 65, 75, "T10"],
    ];
    const tx = db.transaction(() => {
      for (const row of seed) insert.run(...row);
    });
    tx();
  }
}

initDB();

try { db.exec("ALTER TABLE staff ADD COLUMN notified INTEGER DEFAULT 1"); } catch {} // migration

// ─── HELPERS ───
function parseCookies(req) {
  const cookie = req.headers.cookie;
  if (!cookie) return {};
  return Object.fromEntries(
    cookie.split(";").map((c) => c.trim().split("=")).map(([k, v]) => [k, decodeURIComponent(v)])
  );
}

function setTokenCookie(res, token) {
  res.cookie("token", token, {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function authMiddleware(role) {
  return (req, res, next) => {
    const cookies = parseCookies(req);
    const token = req.headers.authorization?.split(" ")[1] || cookies.token;
    if (!token) return res.status(401).json({ error: "No token provided" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role && decoded.role !== "owner")
        return res.status(403).json({ error: "Access denied" });
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

    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (existing) return res.status(400).json({ error: "Email already registered" });

    const hashed = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();
    const result = db.prepare(
      "INSERT INTO users (name, email, password, phone, createdAt) VALUES (?, ?, ?, ?, ?)"
    ).run(name, email, hashed, phone || "", createdAt);

    const token = jwt.sign(
      { id: result.lastInsertRowid, email, name, role: "user" },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    setTokenCookie(res, token);
    res.json({ token, user: { id: result.lastInsertRowid, name, email, role: "user" } });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/users/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: "user" },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    setTokenCookie(res, token);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: "user" } });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/staff/register", authMiddleware("owner"), async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: "Name, email, password required" });

    const existing = db.prepare("SELECT id FROM staff WHERE email = ?").get(email);
    if (existing) return res.status(400).json({ error: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();
    const result = db.prepare(
      "INSERT INTO staff (name, email, password, phone, status, addedBy, createdAt) VALUES (?, ?, ?, ?, 'approved', ?, ?)"
    ).run(name, email, hashed, phone || "", req.user.id, createdAt);

    res.json({ staff: { id: result.lastInsertRowid, name, email, status: "approved" } });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/staff/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const staff = db.prepare("SELECT * FROM staff WHERE email = ?").get(email);
    if (!staff || !(await bcrypt.compare(password, staff.password)))
      return res.status(401).json({ error: "Invalid credentials" });

    if (staff.status === "pending")
      return res.status(403).json({ error: "Your account is pending owner approval", pending: true });
    if (staff.status === "rejected")
      return res.status(403).json({ error: "Owner has rejected your request." });

    const showApproval = staff.notified === 0;
    if (staff.notified === 0) {
      db.prepare("UPDATE staff SET notified = 1 WHERE id = ?").run(staff.id);
    }

    const token = jwt.sign(
      { id: staff.id, email: staff.email, name: staff.name, role: "staff" },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    setTokenCookie(res, token);
    res.json({
      token,
      user: { id: staff.id, name: staff.name, email: staff.email, role: "staff" },
      showApproval,
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/staff/request", async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: "Name, email, password required" });

    const existing = db.prepare("SELECT id FROM staff WHERE email = ?").get(email);
    if (existing) return res.status(400).json({ error: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();
    const result = db.prepare(
      "INSERT INTO staff (name, email, password, phone, status, createdAt) VALUES (?, ?, ?, ?, 'pending', ?)"
    ).run(name, email, hashed, phone || "", createdAt);

    res.json({
      message: "Registration request sent. Waiting for owner approval.",
      staff: { id: result.lastInsertRowid, name, email, status: "pending" },
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/owner/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (email !== "owner@cafe.com")
      return res.status(401).json({ error: "Invalid credentials" });
    if (password !== "owner123")
      return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: 0, email: "owner@cafe.com", name: "Owner", role: "owner" },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    setTokenCookie(res, token);
    res.json({ token, user: { id: 0, name: "Owner", email: "owner@cafe.com", role: "owner" } });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ─── SESSION RESTORE ───

app.get("/api/auth/me", (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies.token;
  if (!token) return res.json({ user: null });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({
      user: { id: decoded.id, name: decoded.name, email: decoded.email, role: decoded.role },
      token,
    });
  } catch {
    res.json({ user: null });
  }
});

// ─── STAFF MANAGEMENT (Owner) ───

app.get("/api/staff/pending", authMiddleware("owner"), (req, res) => {
  const rows = db.prepare("SELECT * FROM staff WHERE status = 'pending'").all();
  res.json(rows);
});

app.get("/api/staff/all", authMiddleware("owner"), (req, res) => {
  const rows = db.prepare("SELECT * FROM staff").all();
  res.json(rows);
});

app.post("/api/staff/approve", authMiddleware("owner"), (req, res) => {
  try {
    const { staffId } = req.body;
    const result = db.prepare("UPDATE staff SET status = 'approved', notified = 0 WHERE id = ?").run(staffId);
    if (result.changes === 0) return res.status(404).json({ error: "Staff not found" });
    const staff = db.prepare("SELECT id, name, email, status FROM staff WHERE id = ?").get(staffId);
    res.json({ message: "Staff approved", staff });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/staff/reject", authMiddleware("owner"), (req, res) => {
  try {
    const { staffId } = req.body;
    const result = db.prepare("UPDATE staff SET status = 'rejected' WHERE id = ?").run(staffId);
    if (result.changes === 0) return res.status(404).json({ error: "Staff not found" });
    res.json({ message: "Staff rejected" });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ─── BOOKINGS ───

app.post("/api/bookings/create", authMiddleware("user"), (req, res) => {
  try {
    const { date, time, guests, tableId } = req.body;
    if (!date || !time || !guests || !tableId)
      return res.status(400).json({ error: "All fields required" });

    const table = db.prepare("SELECT * FROM tables WHERE id = ?").get(tableId);
    if (!table) return res.status(400).json({ error: "Invalid table" });
    if (guests > table.capacity)
      return res.status(400).json({ error: `Table capacity is ${table.capacity} guests` });

    const conflict = db.prepare(
      "SELECT id FROM bookings WHERE tableId = ? AND date = ? AND time = ? AND status = 'confirmed'"
    ).get(tableId, date, time);
    if (conflict)
      return res.status(400).json({ error: "Table already booked for this time slot" });

    const createdAt = new Date().toISOString();
    const result = db.prepare(
      "INSERT INTO bookings (userId, userName, userEmail, date, time, guests, tableId, tableLabel, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', ?)"
    ).run(req.user.id, req.user.name, req.user.email, date, time, guests, tableId, table.label, createdAt);

    const booking = db.prepare("SELECT * FROM bookings WHERE id = ?").get(result.lastInsertRowid);
    res.json({ booking });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/tables/available", (req, res) => {
  const { date, time, guests } = req.query;
  const allTables = db.prepare("SELECT * FROM tables").all();

  const bookedRows = db.prepare(
    "SELECT tableId FROM bookings WHERE date = ? AND time = ? AND status = 'confirmed'"
  ).all(date, time);
  const bookedIds = bookedRows.map((r) => r.tableId);

  const available = allTables.filter((t) => !bookedIds.includes(t.id));
  const filtered = guests ? available.filter((t) => t.capacity >= parseInt(guests)) : available;
  const booked = allTables.filter((t) => bookedIds.includes(t.id));

  res.json({ available: filtered, booked, all: allTables });
});

app.get("/api/bookings/my", authMiddleware("user"), (req, res) => {
  const rows = db.prepare("SELECT * FROM bookings WHERE userId = ?").all(req.user.id);
  res.json(rows);
});

app.post("/api/bookings/cancel", authMiddleware("user"), (req, res) => {
  try {
    const { bookingId } = req.body;
    const booking = db.prepare("SELECT * FROM bookings WHERE id = ? AND userId = ?").get(bookingId, req.user.id);
    if (!booking) return res.status(404).json({ error: "Booking not found" });
    if (booking.status !== "confirmed") return res.status(400).json({ error: "Booking is already cancelled" });

    const today = new Date().toISOString().split("T")[0];
    const isSameDay = booking.date === today;

    db.prepare("UPDATE bookings SET status = 'cancelled' WHERE id = ?").run(bookingId);
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

const OFFERS_FILE = path.join(DATA_DIR, "offers.json");
const UPLOADS_DIR = path.join(__dirname, "public", "uploads");
if (!require("fs").existsSync(UPLOADS_DIR)) require("fs").mkdirSync(UPLOADS_DIR, { recursive: true });

function loadOffers() {
  try { return JSON.parse(require("fs").readFileSync(OFFERS_FILE, "utf8")); } catch { return { offers: [] }; }
}

function saveOffers(data) {
  require("fs").writeFileSync(OFFERS_FILE, JSON.stringify(data));
}

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
      require("fs").writeFileSync(path.join(UPLOADS_DIR, filename), buffer);
      if (offer.image && offer.image !== `/uploads/${filename}`) {
        const oldPath = path.join(__dirname, "public", offer.image);
        try { require("fs").unlinkSync(oldPath); } catch {}
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
      try { require("fs").unlinkSync(oldPath); } catch {}
    }
    offer.image = null;
    saveOffers(data);
    res.json({ message: "Image removed", offers: data.offers });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ─── STAFF DASHBOARD ───

app.get("/api/users/all", authMiddleware("staff"), (req, res) => {
  const rows = db.prepare("SELECT id, name, email, phone, createdAt FROM users").all();
  res.json(rows);
});

app.get("/api/bookings/all", authMiddleware("staff"), (req, res) => {
  const rows = db.prepare("SELECT * FROM bookings").all();
  res.json(rows);
});

app.listen(PORT, () => {
  console.log(`Cafe Management Server running on http://localhost:${PORT}`);
  console.log(`Owner login: owner@cafe.com / owner123`);
});
