const rateLimit = require("express-rate-limit");
// ipKeyGenerator collapses an IPv6 address to its /56 subnet. Without it a single
// IPv6 client gets a fresh key per address and walks straight past the limit.
const { ipKeyGenerator } = require("express-rate-limit");
const MongoStore = require("rate-limit-mongo");
const keys = require("../config/keys");

// Store all limiter counters in the existing Mongo database (no new infra).
// expireTimeMs must match each limiter's windowMs.
function mongoStore(collectionName, windowMs) {
  return new MongoStore({
    uri: keys.MONGO_URI,
    collectionName,
    expireTimeMs: windowMs,
    errorHandler: console.error,
  });
}

// Key by IP + email so one account can't be hammered from many IPs,
// and one IP can't hammer many accounts.
function ipPlusEmail(req) {
  const email = (req.body && req.body.temail ? req.body.temail : "")
    .toString()
    .toLowerCase();
  return `${ipKeyGenerator(req.ip)}:${email}`;
}

const message = { message: "Too many attempts. Please try again later." };

// /login : 5 attempts per 15 min per IP+email
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true, // sends RateLimit-* and Retry-After headers
  legacyHeaders: false,
  keyGenerator: ipPlusEmail,
  store: mongoStore("rl_login", 15 * 60 * 1000),
  message: { message: "Too many login attempts. Please try again later." },
});

// /register : 3 per hour per IP
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  store: mongoStore("rl_register", 60 * 60 * 1000),
  message,
});

// /sendResetPasswordCode : 3 per hour per email
const resetCodeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipPlusEmail,
  store: mongoStore("rl_reset_send", 60 * 60 * 1000),
  message,
});

// /validateResetCode : 5 per hour per email
const validateCodeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipPlusEmail,
  store: mongoStore("rl_reset_validate", 60 * 60 * 1000),
  message,
});

// Global safety net : 100 requests per minute per IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  store: mongoStore("rl_global", 60 * 1000),
  message,
});

module.exports = {
  loginLimiter,
  registerLimiter,
  resetCodeLimiter,
  validateCodeLimiter,
  globalLimiter,
};