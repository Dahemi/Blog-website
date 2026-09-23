const { model, Schema } = require("mongoose");

const { ObjectId } = Schema;

// [CWE-640] Fix: server-side record of every issued password-reset ticket, so a ticket can
// be consumed exactly once. Mirrors the atomic single-use rotation used for refresh tokens.
// The TTL index purges records automatically, so nothing accumulates.
const passwordResetTicketSchema = new Schema(
  {
    jti: {
      type: String,
      required: true,
      unique: true,
    },
    user: {
      type: ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    // Null until the ticket is spent. The compare-and-set in consumeResetTicket relies on it.
    usedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true },
);

passwordResetTicketSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = model("PasswordResetTicket", passwordResetTicketSchema);
