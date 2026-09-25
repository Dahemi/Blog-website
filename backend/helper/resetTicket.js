const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const keys = require("../config/keys");
const PasswordResetTicket = require("../models/PasswordResetTicket");

// [CWE-640] Fix: the credential that authorises a password change is now a short-lived,
// single-purpose ticket. It is signed by the server (so a client cannot mint one), names
// the user in a signed claim (so the target cannot be chosen by the caller), and expires in
// five minutes. Because `purpose` is verified on use, a ticket cannot be repurposed as an
// access token even though both are signed with the same key.
const RESET_TICKET_TTL = "5m";
const RESET_TICKET_TTL_MS = 5 * 60 * 1000;
const RESET_PURPOSE = "password-reset";

const readTicket = (rawTicket) => {
  if (!rawTicket || typeof rawTicket !== "string") return null;
  try {
    const payload = jwt.verify(rawTicket, keys.TOKEN_SECRET);
    if (payload.purpose !== RESET_PURPOSE) return null;
    if (!payload.userId || !payload.jti) return null;
    return payload;
  } catch (error) {
    // Wrong signature, tampered payload, or expired. All are reported identically to the
    // caller so a failed attempt reveals nothing about why it failed.
    return null;
  }
};

const issueResetTicket = async (userId) => {
  const jti = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + RESET_TICKET_TTL_MS);

  await PasswordResetTicket.create({ jti, user: userId, expiresAt });

  return jwt.sign(
    { userId: userId.toString(), purpose: RESET_PURPOSE, jti },
    keys.TOKEN_SECRET,
    { expiresIn: RESET_TICKET_TTL },
  );
};

// Signature/expiry/purpose check with NO side effect. changePassword validates the new
// password first and only then consumes, so a password that fails the policy can be retried
// without forcing the user to restart the whole reset flow.
const verifyResetTicket = (rawTicket) => {
  const payload = readTicket(rawTicket);
  return payload ? { ok: true, userId: payload.userId } : { ok: false };
};

// [CWE-640] Fix: single-use enforcement. The atomic findOneAndUpdate means only the first
// caller can flip usedAt from null; a replay — or a concurrent second request — matches no
// document and is rejected.
const consumeResetTicket = async (rawTicket) => {
  const payload = readTicket(rawTicket);
  if (!payload) return { ok: false };

  const claimed = await PasswordResetTicket.findOneAndUpdate(
    { jti: payload.jti, usedAt: null },
    { $set: { usedAt: new Date() } },
  );

  if (!claimed) return { ok: false };
  return { ok: true, userId: payload.userId };
};

module.exports = {
  RESET_TICKET_TTL,
  RESET_TICKET_TTL_MS,
  RESET_PURPOSE,
  issueResetTicket,
  verifyResetTicket,
  consumeResetTicket,
};
