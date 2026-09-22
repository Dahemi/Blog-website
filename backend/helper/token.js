const jwt = require("jsonwebtoken");
const keys = require("../config/keys");

// [CWE-613] Fix: access tokens were minted with a hardcoded 15-day lifetime, so a
// stolen token stayed valid for weeks. Access tokens are now short-lived by default
// (15 minutes) and long-lived sessions are carried by rotating refresh tokens instead.
const ACCESS_TOKEN_EXPIRY = "15m";

exports.ACCESS_TOKEN_EXPIRY = ACCESS_TOKEN_EXPIRY;

// [CWE-613] Fix: default the lifetime to 15m so no caller can fall back to a
// long-lived token. Callers may still override explicitly when required.
exports.generateToken = (payload, expired = ACCESS_TOKEN_EXPIRY) => {
  return jwt.sign(payload, keys.TOKEN_SECRET, {
    expiresIn: expired,
  });
};
