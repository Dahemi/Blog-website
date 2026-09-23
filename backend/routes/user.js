const express = require("express");
const keys = require("../config/keys");

const { generateToken } = require("../helper/token");
// [CWE-613] Fix: session continuity now comes from rotating server-side refresh tokens.
const {
  revokeRefreshToken,
  clearRefreshCookie,
  issueRefreshToken,
  setRefreshCookie,
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
  findOutUser,
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

const { google_auth, google_auth_callback } = require("../controllers/Auth");

var passport = require("passport");
const OAuthStrategy = require("passport-oauth").OAuthStrategy;
var GoogleStrategy = require("passport-google-oidc");

const router = express.Router();
const app = express();
const { authUser } = require("../middleware/auth");
// app.use(passport.initialize());
// app.use(passport.session());

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

router.post("/register", register);
router.post("/checkotpv", checkotpv);

router.post("/checkifverify", checkifverify);
router.post("/login", login);
// [CWE-613] Fix: dedicated endpoint to exchange a refresh token for a new access token.
router.post("/auth/refresh", refreshAccessToken);
router.post("/sendmail", sendmail);
router.post("/verifycode", verifycode);
router.put("/uploadprofile", authUser, uploadprofile);
router.get("/getUser/:userId", getUser);
router.post("/findOutUser", findOutUser);
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

const register_google = async (req) => {
  try {
    const { name, temail, password, image } = req.body;

    const check = await User.findOne({ temail });
    if (check) {
      return res.status(400).json({
        message: "This email already exists,try again with a different email",
      });
    }

    const hashed_password = await bcrypt.hash(password, 10);
    const user = await new User({
      name: name,
      email: temail,
      password: hashed_password,
      verify: true,
      picture: image,
    }).save();
    const token = generateToken({ id: user._id.toString() }, "15d");
    res.send({
      id: user._id,
      name: user.name,
      picture: user.picture,
      token: token,
      message: "Register Success !",
    });
  } catch (error) {
    // console.log(error);
    return res.status(500).json({ message: error.message });
  }
};

// passport.use(new GoogleStrategy({
//   clientID: process.env.GOOGLE_CLIENT,
//   clientSecret: process.env.GOOGLE_SECRET,
//   callbackURL: `${process.env.REACT_APP_FRONTEND_URL}`,
//   passReqToCallback: true
// },
//   function (req, acc, ref, profile, done) {
//     CSSConditionRule.log(profile)
//     return done(null, profile)
//   }
// ))

// router.get(
//   "/auth/google",
//   passport.authenticate("google", { scope: ['profile', 'email'] }, { failureRedirect: '/login/failed', failureMessage: true }),
//   google_auth
// );

// router.get(
//   "/auth/google/callback",
//   passport.authenticate("google", {
//     failureRedirect: "/login/failed"
//   }),
//   google_auth_callback
// );

router.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] }),
);

router.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: `${keys.FRONTEND_URL}/login`,
  }),
  // [CWE-384] Fix: session fixation. Previously this used passport's `successRedirect`,
  // which kept the session identifier that existed *before* authentication. An identifier
  // captured or planted pre-login would therefore still be valid post-login. We now handle
  // the callback ourselves, regenerate the session id, and re-login so the authenticated
  // identity lives on the new session. The redirect target is unchanged.
  (req, res) => {
    const authenticatedUser = req.user;
    req.session.regenerate((regenerateErr) => {
      if (regenerateErr) {
        return res.redirect(`${keys.FRONTEND_URL}/login`);
      }
      req.login(authenticatedUser, (loginErr) => {
        if (loginErr) {
          return res.redirect(`${keys.FRONTEND_URL}/login`);
        }
        return res.redirect(`${keys.FRONTEND_URL}/`);
      });
    });
  },
);

router.get("/login/failed", (req, res) => {
  res.status(401).json({
    success: false,
    message: " Authentication has been failded ! ",
  });
});

router.post("/login/success", async (req, res) => {
  if (req.isAuthenticated()) {
    // [CWE-384] Fix: rotate the session identifier now that authentication has succeeded.
    // regenerate() clears the session's data, which includes passport's serialized user,
    // so re-login with the same user afterwards or req.isAuthenticated() would be false on
    // subsequent requests and the silent re-auth on the client would break.
    const authenticatedUser = req.user;
    try {
      await regenerateSession(req);
      await loginIntoFreshSession(req, authenticatedUser);
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: "Un-successfull",
        user: null,
      });
    }
    // [CWE-613] Fix: issue a 15m access token (default) and hand back a rotating refresh
    // cookie, instead of a single 15-day JWT that could not be revoked.
    const token = generateToken({ id: req.user._id.toString() });
    const { rawToken } = await issueRefreshToken(req.user._id);
    setRefreshCookie(res, rawToken);
    return res.status(201).send({
      id: req.user._id,
      name: req.user.name,
      picture: req.user.picture,
      token: token,
      likes: req.user.likes,
      bookmarks: req.user.bookmarks,
    });
    // res.status(200).json({
    //   success: true,
    //   message: "successfull",
    //   user: { id: req.user._id, name: req.user.name, email: req.user.email, googleId: req.user.googleId, picture: req.user.picture }
    // });
  } else {
    // console.log("failed");
    return res.status(401).json({
      success: false,
      message: "Un-successfull",
      user: null,
    });
  }
});
//Logout
router.get("/logout", async (req, res) => {
  try {
    req.logout((err) => {
      if (err) {
        return res.status(400).json("Couldn't logout");
      }
    });
    // [CWE-613] Fix: revoke the server-side refresh token on logout. Previously logout
    // only cleared cookies, leaving a long-lived credential able to mint new tokens.
    const rawToken = req.cookies ? req.cookies[REFRESH_COOKIE_NAME] : null;
    await revokeRefreshToken(rawToken);
    clearRefreshCookie(res);
    res.cookie("session", "", { expires: new Date(0) });
    res.clearCookie("sessionId");
    res.status(200).json({ success: true });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

module.exports = router;
