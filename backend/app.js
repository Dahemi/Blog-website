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

// --- V13: bound uploads before anything touches the filesystem -------------
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024; // 5 MB
app.use(
  fileUpload({
    useTempFiles: true,
    tempFileDir: require("os").tmpdir(),
    limits: { fileSize: MAX_UPLOAD_BYTES },
    abortOnLimit: true,      // reject, don't silently truncate
    responseOnLimit: "File exceeds the 5 MB limit.",
    safeFileNames: true,     // strip path separators from the supplied name
    preserveExtension: 8,
  }),
);

app.use("/", userRoutes);
require("./servises/passport");
app.use("/", uploadRoutes);
app.use("/", postRoutes);

module.exports = app;
