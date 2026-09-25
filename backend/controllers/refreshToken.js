const User = require("../models/User");
const { generateToken } = require("../helper/token");
const {
  rotateRefreshToken,
  setRefreshCookie,
  clearRefreshCookie,
  REFRESH_COOKIE_NAME,
} = require("../helper/refreshToken");

// [CWE-613] Fix: exchange a valid refresh token for a new short-lived access token.
// The refresh token cookie is single-use: it is rotated on every call, and an already
// consumed token is treated as stolen (all of that user's sessions are revoked).
exports.refreshAccessToken = async (req, res) => {
  try {
    const rawToken = req.cookies ? req.cookies[REFRESH_COOKIE_NAME] : null;
    const result = await rotateRefreshToken(rawToken);

    if (!result.ok) {
      // [CWE-613] Fix: never keep serving a dead credential; drop the cookie on failure.
      clearRefreshCookie(res);
      return res.status(401).json({
        message: "Invalid or expired refresh token",
        code: "REFRESH_TOKEN_INVALID",
      });
    }

    const user = await User.findById(result.userId).select("name picture");
    if (!user) {
      clearRefreshCookie(res);
      return res.status(401).json({
        message: "Invalid or expired refresh token",
        code: "REFRESH_TOKEN_INVALID",
      });
    }

    // [CWE-613] Fix: hand back the rotated cookie plus a fresh 15m access token.
    setRefreshCookie(res, result.rawToken);
    const token = generateToken({ id: result.userId.toString() });

    return res.status(200).json({
      token,
      id: result.userId,
      name: user.name,
      picture: user.picture,
    });
  } catch (error) {
    // Deliberately not logging the token or the error object (may contain credentials).
    return res.status(500).json({ message: "Internal Server Error" });
  }
};
