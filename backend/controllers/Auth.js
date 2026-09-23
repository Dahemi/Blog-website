const crypto = require("crypto");
const { OAuth2Client } = require("google-auth-library");
const User = require("../models/User");
const { generateToken } = require("../helper/token");
const keys = require("../config/keys");

const REDIRECT_URI = `${keys.BACKEND_URL}/auth/google/callback`;
const FRONTEND_CALLBACK = `${keys.FRONTEND_URL}/oauth/callback`;

const oauthClient = new OAuth2Client({
  clientId: keys.GOOGLE_CLIENT_ID,
  clientSecret: keys.GOOGLE_CLIENT_SECRET,
  redirectUri: REDIRECT_URI,
});

// RFC 7636 §4.1 — the verifier is a high-entropy URL-safe string.
const randomUrlSafe = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");

// RFC 7636 §4.2 — S256: challenge = BASE64URL(SHA256(ASCII(verifier))).
// "plain" is permitted by the RFC but offers no protection against anyone who can
// observe the authorization request, so S256 is the only acceptable method.
const s256 = (verifier) =>
  crypto.createHash("sha256").update(verifier, "ascii").digest("base64url");

const DEFAULT_AVATAR =
  "https://res.cloudinary.com/dmhcnhtng/image/upload/v1643044376/avatars/default_pic_jeaybr.png";
const isDefaultAvatar = (p) => !p || p === DEFAULT_AVATAR;

/** GET /auth/google — start the flow. */
exports.google_auth = async (req, res) => {
  try {
    const state = randomUrlSafe(32);        // CSRF protection on the callback
    const nonce = randomUrlSafe(32);        // binds the ID token to this request
    const codeVerifier = randomUrlSafe(32); // PKCE secret — never leaves this server
    const codeChallenge = s256(codeVerifier);

    // Held server-side, so none of these appear in the URL, in browser history,
    // or anywhere client-side JavaScript can reach.
    req.session.oidc = { state, nonce, codeVerifier, createdAt: Date.now() };

    // Persist before redirecting, or the callback can arrive before the session
    // store has finished writing.
    req.session.save((err) => {
      if (err) return res.redirect(`${FRONTEND_CALLBACK}#error=session_error`);

      const authUrl = oauthClient.generateAuthUrl({
        access_type: "online",              // we don't need a Google refresh token
        scope: ["openid", "email", "profile"],
        state,
        nonce,
        code_challenge_method: "S256",
        code_challenge: codeChallenge,
        prompt: "select_account",
      });
      return res.redirect(authUrl);
    });
  } catch (error) {
    return res.redirect(`${FRONTEND_CALLBACK}#error=auth_init_failed`);
  }
};

/** GET /auth/google/callback — Google redirects the browser back here. */
exports.google_auth_callback = async (req, res) => {
  const fail = (reason) =>
    res.redirect(`${FRONTEND_CALLBACK}#error=${encodeURIComponent(reason)}`);

  try {
    const { code, state, error: providerError } = req.query;

    if (providerError) return fail("access_denied");     // user declined consent
    if (!code || !state) return fail("missing_code_or_state");

    // Pull the stashed values, then clear them immediately — single-use, so a
    // replayed callback cannot reuse them.
    const stash = req.session.oidc;
    delete req.session.oidc;
    if (!stash) return fail("no_pending_authorization");

    // Expire stale authorizations; 10 minutes is generous for a consent screen.
    if (Date.now() - stash.createdAt > 10 * 60 * 1000) return fail("authorization_expired");

    // --- STATE CHECK: the anti-CSRF control. Constant-time comparison so response
    //     timing cannot leak the expected value.
    const a = Buffer.from(String(state));
    const b = Buffer.from(String(stash.state));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return fail("state_mismatch");
    }

    // --- PKCE: present the verifier. Google recomputes SHA256(verifier) and compares
    //     it to the challenge stored at authorization time, so a stolen code alone
    //     is not redeemable.
    const { tokens } = await oauthClient.getToken({
      code: String(code),
      codeVerifier: stash.codeVerifier,
    });
    if (!tokens.id_token) return fail("no_id_token");

    // --- ID TOKEN VERIFICATION: RS256 signature against Google's JWKS (fetched and
    //     cached by google-auth-library, so key rotation is handled), plus aud and exp.
    const ticket = await oauthClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: keys.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload) return fail("invalid_id_token");

    // --- NONCE CHECK: proves this ID token was issued for *our* authorization
    //     request, not obtained elsewhere and injected here.
    if (payload.nonce !== stash.nonce) return fail("nonce_mismatch");

    // Defence in depth: verifyIdToken checks iss, but assert it in our own code too.
    if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com") {
      return fail("unexpected_issuer");
    }

    // --- EMAIL_VERIFIED CHECK: the control the original code was missing. Without it,
    //     an attacker who registers the victim's address at the provider gets linked
    //     to the victim's existing local account below.
    if (!payload.email || payload.email_verified !== true) {
      return fail("email_not_verified");
    }

    const googleId = payload.sub;   // stable provider-assigned subject identifier
    const email = payload.email.toLowerCase();

    // Match on `sub` first: an email address can be reassigned, `sub` cannot.
    let user = await User.findOne({ googleId });

    if (!user) {
      user = await User.findOne({ email });
      if (user) {
        // Link. Safe *only* because email_verified was asserted above.
        user.googleId = googleId;
        user.authProvider = user.password ? "both" : "google";
        user.verify = true;                   // Google asserted the address
        if (!user.name && payload.name) user.name = payload.name;
        if (payload.picture && isDefaultAvatar(user.picture)) user.picture = payload.picture;
        await user.save();
      } else {
        user = await new User({
          googleId,
          email,
          name: payload.name || email.split("@")[0],
          picture: payload.picture || undefined,
          verify: true,                       // fixes V11 for Google-created users
          authProvider: "google",
          likeslist: {},
          bookmarkslist: {},
        }).save();
      }
    }

    // --- SESSION REGENERATION: a session ID fixed by an attacker before login must
    //     not survive into the authenticated state (CWE-384). Mirrors Imadh's V12 fix,
    //     preserved here since this callback replaces the one that fix was applied to.
    req.session.regenerate((regenErr) => {
      if (regenErr) return fail("session_error");

      req.session.userId = user._id.toString();

      // 15 minutes — consistent with Imadh's V14 work, not a new decision made here.
      const token = generateToken({ id: user._id.toString() }, "15m");

      // Returned in the URL *fragment*, not the query string. Fragments are never
      // sent to a server, so the token cannot appear in access logs, proxy logs,
      // or a Referer header.
      const fragment = new URLSearchParams({
        token,
        id: user._id.toString(),
        name: user.name || "",
        picture: user.picture || "",
        // Every client component reads user.likes/user.bookmarks as arrays without a
        // null-check (see PostCard.js's user.likes.push(...)) — omitting these would
        // crash the very first like/bookmark click after a Google login.
        likes: JSON.stringify(user.likes || []),
        bookmarks: JSON.stringify(user.bookmarks || []),
      }).toString();

      return res.redirect(`${FRONTEND_CALLBACK}#${fragment}`);
    });
  } catch (error) {
    // Never leak provider error detail to the browser — it can disclose whether an
    // account exists. Log server-side, return an opaque reason.
    console.error("[oidc] callback failed:", error.message);
    return fail("authentication_failed");
  }
};
