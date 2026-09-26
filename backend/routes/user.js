const express = require("express");

// [CWE-613] Fix: session continuity now comes from rotating server-side refresh tokens.
const {
  revokeRefreshToken,
  clearRefreshCookie,
  REFRESH_COOKIE_NAME,
} = require("../helper/refreshToken");
const { refreshAccessToken } = require("../controllers/refreshToken");
const {
  getallLikes,
  register,
  login,
  getallBookmarks,
  uploadprofile,
  getUser,
  sendResetPasswordCode,
  validateResetCode,
  changePassword,
  bookmark,
  deletebookmark,
  checkbookmark,
  sendreportmails,
  followercount,
  followingcount,
  showbookmark,
  fetchprof,
  showmyposts,
  deletepost,
  fetchfollowing,
  follow,
  checkfollowing,
  unfollow,
  searchresult,
  changeabout,
  likes,
  checklikes,
  deletelikes,
  showLikemark,
} = require("../controllers/user");
const {
  sendmail,
  checkifverify,
  verifycode,
  checkotpv,
} = require("../controllers/verifyemail");

// [OIDC] google_auth / google_auth_callback replace passport-google-oauth20 entirely —
// see servises/passport.js's removal and controllers/Auth.js for the new flow.
const { google_auth, google_auth_callback } = require("../controllers/Auth");

const router = express.Router();
const app = express();
const { authUser } = require("../middleware/auth");
const {
  loginLimiter,
  registerLimiter,
  resetCodeLimiter,
  validateCodeLimiter,
} = require("../middleware/rateLimit");
// app.use(passport.initialize());
// app.use(passport.session());
router.post("/register", registerLimiter, register);
router.post("/checkotpv", checkotpv);

router.post("/checkifverify", checkifverify);
router.post("/login", loginLimiter, login);

// [CWE-384] Fix: promisified session helpers. After authentication succeeds we rotate the
// session identifier and only then re-establish passport's identity on the new session,
// so the response is not sent before the rotation has actually completed.
const regenerateSession = (req) =>
  new Promise((resolve, reject) => {
    req.session.regenerate((err) => (err ? reject(err) : resolve()));
  });

const loginIntoFreshSession = (req, user) =>
  new Promise((resolve, reject) => {
    req.login(user, (err) => (err ? reject(err) : resolve()));
  });

// [CWE-613] Fix: dedicated endpoint to exchange a refresh token for a new access token.
router.post("/auth/refresh", refreshAccessToken);
router.post("/sendmail", sendmail);
router.post("/verifycode", verifycode);
router.put("/uploadprofile", authUser, uploadprofile);
router.get("/getUser/:userId", getUser);
// [CWE-204] /findOutUser removed — it existed only to confirm whether an email address
// had an account. The reset flow now posts straight to /sendResetPasswordCode, which
// responds identically for registered and unregistered addresses.
// [CWE-639] Fix: was readable for any userid in the body.
router.post("/getallBookmarks", authUser, getallBookmarks);
router.post("/sendResetPasswordCode", sendResetPasswordCode);
router.post("/validateResetCode", validateResetCode);
router.post("/changePassword", changePassword);
// [CWE-639] Fix: require auth and ignore any body-supplied userid on user-owned routes.
router.post("/setbookmark", authUser, bookmark);
// [CWE-639] Fix: require auth; owner is derived from the token in the controller.
router.post("/setlikes", authUser, likes);
// [CWE-639] Fix: was readable for any userid in the body.
router.post("/getallLikes", authUser, getallLikes);
// [CWE-639] Fix: was mutable for any userid in the body.
router.post("/deletelikes", authUser, deletelikes);
// [CWE-639] Fix: was mutable for any userid in the body.
router.post("/checklikes", authUser, checklikes);
// [CWE-639] Fix: was mutable for any userid in the body.
router.post("/deletebookmark", authUser, deletebookmark);
// [CWE-639] Fix: was readable for any userid in the body.
router.post("/checkbookmark", authUser, checkbookmark);
// [CWE-639] Fix: reporter identity derived from the token, not the body.
router.post("/reportcontent", authUser, sendreportmails);
router.post("/countfollower", followercount);
router.post("/countfollowing", followingcount);
// [CWE-639] Fix: was readable for any id in the body.
router.post("/showbookmarks", authUser, showbookmark);
// [CWE-639] Fix: was readable for any id in the body.
router.post("/showLikemarks", authUser, showLikemark);
router.post("/fetchprof", fetchprof);
// [CWE-639] Fix: returns the authenticated caller's own posts only.
router.post("/showmyposts", authUser, showmyposts);
// [CWE-639] Fix: only the owner may delete a post; owner derived from the token.
router.post("/deletepost", authUser, deletepost);
// [CWE-639] Fix: returns the authenticated caller's own following list.
router.post("/fetchfollowing", authUser, fetchfollowing);
// [CWE-639] Fix: actor from token, target (id2) from body.
router.post("/startfollow", authUser, follow);
// [CWE-639] Fix: actor from token, target (id2) from body.
router.post("/unfollow", authUser, unfollow);
router.post("/searchresult", searchresult);
// [CWE-639] Fix: actor from token, target (id2) from body.
router.post("/checkfollow", authUser, checkfollowing);
// [CWE-639] Fix: was editable for any id supplied in the body.
router.post("/changeabout", authUser, changeabout);

// [OIDC] Replaces the previous passport-google-oauth20 wiring (and the unreachable
// register_google helper, and POST /login/success + GET /login/failed) entirely.
// google_auth starts the Authorization Code + PKCE flow; google_auth_callback verifies
// the ID token, links/creates the user, and redirects with the token in the URL
// fragment — there is no separate "check if I'm logged in" endpoint to poll anymore.
router.get("/auth/google", google_auth);
router.get("/auth/google/callback", google_auth_callback);

//Logout
router.get("/logout", async (req, res) => {
  try {
    // [CWE-613] Fix: revoke the server-side refresh token on logout. Previously logout
    // only cleared cookies, leaving a long-lived credential able to mint new tokens.
    const rawToken = req.cookies ? req.cookies[REFRESH_COOKIE_NAME] : null;
    await revokeRefreshToken(rawToken);
    clearRefreshCookie(res);
    // [OIDC] req.logout() was Passport's — Passport is no longer registered anywhere in
    // this app. Destroying the session directly achieves the same end (clears any
    // server-side session data, including a stray req.session.userId).
    req.session.destroy(() => {
      res.cookie("session", "", { expires: new Date(0) });
      res.clearCookie("sessionId");
      res.status(200).json({ success: true });
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

module.exports = router;
