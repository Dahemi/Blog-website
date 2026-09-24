const jwt = require("jsonwebtoken");
const keys = require("../config/keys");

exports.authUser = async (req, res, next) => {
  try {
    // [CWE-613] Fix: parse the header strictly. The previous tmp.slice(7) mangled any
    // value that did not start with "Bearer ", and a malformed header silently passed "".
    const header = req.header("Authorization") || "";
    const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
    if (!token) {
      return res.status(401).json({
        message: "Invalid Authentification",
        code: "TOKEN_MISSING",
      });
    }
    jwt.verify(token, keys.TOKEN_SECRET, (err, user) => {
      if (err) {
        // [CWE-613] Fix: expired tokens now return 401 with a coded reason (previously a
        // blanket 400). This lets the client distinguish "expired, try refreshing" from a
        // genuinely bad request, which is what enables silent refresh instead of a logout.
        const expired = err.name === "TokenExpiredError";
        return res.status(401).json({
          message: expired ? "Token expired" : "Invalid Authentification",
          code: expired ? "TOKEN_EXPIRED" : "TOKEN_INVALID",
        });
      }
      req.user = user;
      next();
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};
