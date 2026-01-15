require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const fetch = require("node-fetch");
const passport = require("passport");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");

const db = require("./db");

// dùng auth mới (access token cookie)
const { signAccessToken, setAccessCookie, clearAuthCookies } = require("./auth");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": ["'self'", "https://www.google.com", "https://www.gstatic.com"],
        "frame-src": ["'self'", "https://www.google.com"],
      },
    },
  })
);

// Static
app.use(express.static(path.join(__dirname, "..", "public")));
app.get("/", (req, res) => res.redirect("/login.html"));

// Rate limit
app.use("/api/login", rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }));
app.use("/api/register", rateLimit({ windowMs: 60 * 60 * 1000, max: 20 }));

/** ===== CSRF (double-submit cookie) ===== */
function setCsrfCookie(res) {
  const token = crypto.randomBytes(32).toString("base64url");
  res.cookie("csrf_token", token, {
    httpOnly: false, // frontend đọc để gửi header
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  });
  return token;
}

function csrfGuard(req, res, next) {
  const cookieToken = req.cookies.csrf_token;
  const headerToken = req.headers["x-csrf-token"];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: "CSRF check failed" });
  }

  // Origin check (khuyên bật)
  const origin = req.headers.origin;
  const base = process.env.APP_BASE_URL;
  if (origin && base && origin !== base) {
    return res.status(403).json({ error: "Bad origin" });
  }
  next();
}

app.get("/api/csrf", (req, res) => {
  const t = setCsrfCookie(res);
  res.json({ csrfToken: t });
});

/** ===== reCAPTCHA verify ===== */
async function verifyRecaptcha(token) {
  const secret = process.env.RECAPTCHA_SECRET;
  if (!secret) return false;

  const resp = await fetch("https://www.google.com/recaptcha/api/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ secret, response: token }).toString(),
  });
  const data = await resp.json();
  return data?.success === true;
}

/** ===== Protect blank page ===== */
function requireAuth(req, res, next) {
  const token = req.cookies.access_token;
  if (!token) return res.redirect("/login.html");
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.redirect("/login.html");
  }
}

app.get("/blank", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "blank.html"));
});

/** ===== Register ===== */
app.post("/api/register", csrfGuard, async (req, res) => {
  try {
    const { fullName, email, dob, phone, password, captchaToken } = req.body;

    if (!captchaToken) return res.status(400).json({ error: "Missing captchaToken" });
    const ok = await verifyRecaptcha(captchaToken);
    if (!ok) return res.status(400).json({ error: "Captcha failed" });

    if (!email || !fullName || !password) {
      return res.status(400).json({ error: "Missing required fields: fullName, email, password" });
    }

    const existing = db.prepare("SELECT id FROM users WHERE email=?").get(email.toLowerCase());
    if (existing) return res.status(409).json({ error: "Email already exists" });

    const passwordHash = await bcrypt.hash(password, 12);

    const stmt = db.prepare(`
      INSERT INTO users (full_name, email, dob, phone, password_hash)
      VALUES (?, ?, ?, ?, ?)
    `);
    const info = stmt.run(fullName, email.toLowerCase(), dob || null, phone || null, passwordHash);

    const user = { id: info.lastInsertRowid, email: email.toLowerCase() };

    // set access cookie
    const access = signAccessToken(user);
    setAccessCookie(res, access);

    return res.json({ ok: true, redirect: "/blank" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

/** ===== Login ===== */
app.post("/api/login", csrfGuard, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = db.prepare("SELECT * FROM users WHERE email=?").get((email || "").toLowerCase());
    if (!user || !user.password_hash) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const access = signAccessToken(user);
    setAccessCookie(res, access);

    return res.json({ ok: true, redirect: "/blank" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

/** ===== Logout ===== */
app.post("/api/logout", csrfGuard, (req, res) => {
  clearAuthCookies(res);
  res.json({ ok: true });
});

/**
 * ===== OAuth =====
 * Lưu ý: oauth.js của bạn đang dùng signToken/setAuthCookie (cũ).
 * Nếu bạn muốn giữ OAuth, cần sửa oauth.js sang signAccessToken/setAccessCookie.
 */
// require("./oauth")(app, passport, db, signAccessToken, setAccessCookie);

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on http://localhost:" + port));
