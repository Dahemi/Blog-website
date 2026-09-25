const { z } = require("zod");

// Login accepts the email under the body key `temail` (see controllers/user.js).
// Forcing both fields to be strings blocks type-based NoSQL injection
// (e.g. temail as an object/array) that the global sanitizer does not catch.
const loginSchema = z.object({
  temail: z.string().trim().min(1).max(320),
  password: z.string().min(1).max(128),
});

module.exports = { loginSchema };
