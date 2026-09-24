const { model, Schema } = require("mongoose");

const { ObjectId } = Schema;

// [CWE-613] Fix: refresh tokens are persisted server-side so they can be rotated
// and revoked. Only a SHA-256 hash of the token is stored, never the raw value, so
// a database leak cannot be replayed as a valid credential.
const refreshTokenSchema = new Schema(
  {
    userId: {
      type: ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    tokenHash: {
      type: String,
      required: true,
      unique: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    // Null until the token is consumed by rotation or explicitly revoked.
    revokedAt: {
      type: Date,
      default: null,
    },
    // Hash of the token that replaced this one; lets us trace a rotation chain.
    replacedByHash: {
      type: String,
      default: null,
    },
    userAgent: {
      type: String,
    },
  },
  { timestamps: true },
);

// [CWE-613] Fix: TTL index lets MongoDB purge expired refresh tokens automatically
// instead of leaving dead credentials in the collection indefinitely.
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = model("RefreshToken", refreshTokenSchema);
