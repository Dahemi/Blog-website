const crypto = require("crypto");
const RefreshToken = require("../models/RefreshToken");

// [CWE-613] Fix: refresh tokens live for 7 days but are single-use and rotated on every
// exchange, so the useful lifetime of any individual refresh token is one request.
const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const REFRESH_COOKIE_NAME = "refreshToken";
// Scope the cookie to the auth path so the browser does not attach it to every request.
const REFRESH_COOKIE_PATH = "/auth";
// Cookie maxAge is in milliseconds for Express.
const REFRESH_COOKIE_MAX_AGE_MS = REFRESH_TOKEN_TTL_MS;

// [CWE-613] Fix: opaque 256-bit random token instead of a signed JWT. It carries no
// claims, cannot be forged or decoded, and is meaningless without the stored hash.
const generateOpaqueToken = () => crypto.randomBytes(64).toString("hex");

// [CWE-613] Fix: hash before persisting so the raw credential never touches the database.
const hashToken = (rawToken) =>
  crypto.createHash("sha256").update(rawToken).digest("hex");

// [CWE-613] Fix: httpOnly keeps the refresh token unreadable by JavaScript (XSS cannot
// exfiltrate it), SameSite/Secure protect it in transit and against cross-site sends.
const refreshCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  path: REFRESH_COOKIE_PATH,
  maxAge: REFRESH_COOKIE_MAX_AGE_MS,
});

// [CWE-613] Fix: centralised cookie writer so every issuing path (register, login,
// google login, refresh) sets identical hardening attributes.
const setRefreshCookie = (res, rawToken) => {
  res.cookie(REFRESH_COOKIE_NAME, rawToken, refreshCookieOptions());
};

const clearRefreshCookie = (res) => {
  res.clearCookie(REFRESH_COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    path: REFRESH_COOKIE_PATH,
  });
};

const issueRefreshToken = async (userId, userAgent) => {
  const rawToken = generateOpaqueToken();
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
  await RefreshToken.create({
    userId,
    tokenHash: hashToken(rawToken),
    expiresAt,
    userAgent,
  });
  return { rawToken, expiresAt };
};

const revokeRefreshToken = async (rawToken) => {
  if (!rawToken) return false;
  const revoked = await RefreshToken.findOneAndUpdate(
    { tokenHash: hashToken(rawToken), revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );
  return Boolean(revoked);
};

// [CWE-613] Fix: burn every active refresh token for a user. Used on logout and,
// more importantly, when token reuse is detected (theft response).
const revokeAllForUser = async (userId) => {
  if (!userId) return;
  await RefreshToken.updateMany(
    { userId, revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );
};

// [CWE-613] Fix: single-use rotation. The old token is consumed atomically so two
// concurrent requests cannot both exchange it, and replaying a consumed token is
// treated as theft (all sessions for that user are revoked).
const rotateRefreshToken = async (rawToken) => {
  if (!rawToken) return { ok: false, reason: "missing" };

  const tokenHash = hashToken(rawToken);
  const existing = await RefreshToken.findOne({ tokenHash });

  if (!existing) return { ok: false, reason: "invalid" };

  if (existing.revokedAt) {
    await revokeAllForUser(existing.userId);
    return { ok: false, reason: "reuse", userId: existing.userId };
  }

  if (existing.expiresAt.getTime() <= Date.now()) {
    return { ok: false, reason: "expired", userId: existing.userId };
  }

  const rawTokenNew = generateOpaqueToken();
  const newTokenHash = hashToken(rawTokenNew);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

  // Atomic compare-and-set: only the first request to flip revokedAt from null wins.
  const claimed = await RefreshToken.findOneAndUpdate(
    { tokenHash, revokedAt: null },
    { $set: { revokedAt: new Date(), replacedByHash: newTokenHash } },
  );

  if (!claimed) {
    // Lost the race against a concurrent rotation => the token was already consumed.
    await revokeAllForUser(existing.userId);
    return { ok: false, reason: "reuse", userId: existing.userId };
  }

  await RefreshToken.create({
    userId: claimed.userId,
    tokenHash: newTokenHash,
    expiresAt,
  });

  return { ok: true, rawToken: rawTokenNew, expiresAt, userId: claimed.userId };
};

module.exports = {
  REFRESH_TOKEN_TTL_MS,
  REFRESH_COOKIE_NAME,
  hashToken,
  setRefreshCookie,
  clearRefreshCookie,
  issueRefreshToken,
  revokeRefreshToken,
  revokeAllForUser,
  rotateRefreshToken,
};
