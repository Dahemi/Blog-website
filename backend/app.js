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

app.use(
  cors({
    origin: [keys.BACKEND_URL, keys.FRONTEND_URL],
    // origin: [keys.REACT_APP_BACKEND_URL, keys.REACT_APP_FRONTEND_URL],
    methods: "GET,POST,PUT,DELETE",
    credentials: true,
  }),
);

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

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
    // [CWE-613] Fix: stop persisting sessions for visitors who never authenticated.
    // With `true`, every anonymous request wrote an empty session document to the
    // mySessions collection and issued a session identifier before any login had
    // happened. Passport still persists the session on login, because the successful
    // authentication marks req.session as modified.
    saveUninitialized: false,
    // [CWE-613] Fix: express-session names its cookie "connect.sid" by default, but logout
    // in routes/user.js already calls res.clearCookie("sessionId") and the client removes
    // "sessionId" as well. Under the default name those calls deleted a cookie that never
    // existed, so the real session cookie survived logout. Naming it explicitly makes the
    // existing logout actually clear the session cookie, and stops advertising the
    // framework to clients.
    name: "sessionId",
    store: MongoStore.create({
      mongoUrl: keys.MONGO_URI,
      collectionName: "mySessions",
    }),
    cookie: {
      maxAge: 15 * 24 * 60 * 60 * 1000, // Uncomment if needed for cookie lifespan
      // [CWE-1004] Note: express-session already defaults httpOnly to true. Stated
      // explicitly so the protection is visible in review and cannot be silently
      // dropped by a later edit to this block.
      httpOnly: true,
      // [CWE-613] Note: deliberately NOT "strict". The Google OAuth callback
      // (/auth/google/callback) is a cross-site, top-level redirect from Google, and
      // "strict" withholds the cookie on it — that would drop req.session.passport.user
      // and break login. "lax" still sends the cookie on the top-level GET callback.
      // Production is genuinely cross-site (Vercel frontend + separate API host), so it
      // needs "none" together with secure.
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
