require("dotenv").config();
const express = require("express");
const app = express();
const passport = require("passport");
const session = require("express-session");
// const session = require('cookie-session');
const cors = require("cors");
const fileUpload = require("express-fileupload");
const userRoutes = require("./routes/user.js");
const uploadRoutes = require("./routes/upload.js");
const postRoutes = require("./routes/post.js");
var cookieParser = require("cookie-parser");
var cookieSession = require("cookie-session");
const MongoStore = require("connect-mongo");
const keys = require("./config/keys");
const helmet = require("helmet");

const isProd = process.env.NODE_ENV === "production";

// --- V10: security headers ------------------------------------------------
// The original server sent no CSP, HSTS, X-Frame-Options or X-Content-Type-Options,
// and advertised X-Powered-By: Express.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        // 'unsafe-inline' is required here because Jodit (the rich-text editor)
        // injects inline style attributes at runtime. Documented as an accepted
        // trade-off in report 6.3 — the production answer is a nonce-based CSP,
        // which needs build-tool integration.
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: [
          "'self'", "data:",
          "https://res.cloudinary.com",
          "https://lh3.googleusercontent.com",   // Google profile pictures
        ],
        connectSrc: ["'self'", keys.FRONTEND_URL].filter(Boolean),
        fontSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],   // clickjacking defence at the CSP layer
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: isProd ? [] : null,
      },
    },
    // HSTS only in production. Sending it from http://localhost would pin every
    // teammate's browser to https://localhost — which has no certificate — and
    // break their dev environment for a year.
    hsts: isProd
      ? { maxAge: 31536000, includeSubDomains: true, preload: true }
      : false,
    crossOriginResourcePolicy: { policy: "cross-origin" }, // client is another origin
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    frameguard: { action: "deny" },
  }),
);
app.disable("x-powered-by");

// --- V10: tightened CORS ---------------------------------------------------
// Was: origin: [keys.BACKEND_URL, keys.FRONTEND_URL]
// The backend's own origin was in the allowlist, which is meaningless — a server
// calling itself performs no CORS preflight — and if FRONTEND_URL were unset the
// array would contain `undefined`.
const allowedOrigins = [keys.FRONTEND_URL].filter(Boolean);
if (allowedOrigins.length === 0) {
  throw new Error(
    "REACT_APP_FRONTEND_URL must be set — refusing to start with an empty CORS allowlist",
  );
}
app.use(
  cors({
    origin: allowedOrigins,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    maxAge: 600,
  }),
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));

app.set("trust proxy", 1);
// [CWE-613] Note: cookieParser is what exposes the httpOnly refreshToken cookie to
// req.cookies, which /auth/refresh and /logout rely on.
app.use(cookieParser());
app.use(
  session({
    proxy: true,
    secret: keys.COOKIE_KEY,
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({
      mongoUrl: keys.MONGO_URI,
      collectionName: "mySessions",
    }),
    cookie: {
      maxAge: 15 * 24 * 60 * 60 * 1000, // Uncomment if needed for cookie lifespan
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // "none" for cross-site cookies in production
      secure: process.env.NODE_ENV === "production", // Secure should be true in production (HTTPS)
    },
  }),
);

app.use(passport.initialize());
app.use(passport.session());

app.use(
  fileUpload({
    useTempFiles: true,
  }),
);

app.use("/", userRoutes);
require("./servises/passport");
app.use("/", uploadRoutes);
app.use("/", postRoutes);

module.exports = app;
