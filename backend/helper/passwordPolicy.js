const zxcvbn = require("zxcvbn");

// V15: the original policy was validateLength(password, 6, 15) — a 6-character
// minimum with no complexity check, and a 15-character *maximum* that blocked
// passphrases and password managers. Passwords are bcrypt-hashed to a fixed
// 60-character string, so there was never a storage reason for an upper bound.
const MIN_LENGTH = 12;

// bcrypt silently truncates input beyond 72 bytes, so accepting more than that
// would let two different passwords authenticate the same account. This is a
// real algorithmic bound, not an arbitrary product limit.
const MAX_BYTES = 72;

// zxcvbn score: 0 = too guessable .. 4 = very unguessable. 3 = "safely unguessable".
const MIN_SCORE = 3;

// Single source of truth — the codebase previously hashed at cost 10 in register
// and cost 12 in changePassword, so a user's protection depended on which path
// last set their password.
const BCRYPT_COST = 12;

/**
 * @param {string} password
 * @param {string[]} userInputs  name/email, so zxcvbn penalises passwords derived
 *                               from the user's own identity
 * @returns {{ok: true, score: number} | {ok: false, message: string, score?: number}}
 */
function validatePassword(password, userInputs = []) {
  // The original validateLength threw or silently passed on non-strings, because
  // Number.prototype.length is undefined and every comparison against it is false.
  if (typeof password !== "string") {
    return { ok: false, message: "Password must be a string." };
  }
  if (password.length < MIN_LENGTH) {
    return { ok: false, message: `Password must be at least ${MIN_LENGTH} characters.` };
  }
  if (Buffer.byteLength(password, "utf8") > MAX_BYTES) {
    return { ok: false, message: `Password must be at most ${MAX_BYTES} bytes.` };
  }

  const result = zxcvbn(password, userInputs.filter((v) => typeof v === "string"));

  if (result.score < MIN_SCORE) {
    const hint =
      (result.feedback && (result.feedback.warning || result.feedback.suggestions[0])) ||
      "Try a longer passphrase of several unrelated words.";
    return { ok: false, message: `Password is too easy to guess. ${hint}`, score: result.score };
  }
  return { ok: true, score: result.score };
}

module.exports = { validatePassword, MIN_LENGTH, MAX_BYTES, MIN_SCORE, BCRYPT_COST };
