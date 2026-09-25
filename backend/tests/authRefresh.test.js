// [CWE-613] Regression tests for the short-lived access token + refresh token rotation fix.
// Required scenarios:
//   1. an expired access token returns 401
//   2. a valid refresh token mints a new access token (and rotates the cookie)
//   3. a used (rotated) refresh token cannot be reused
// Plus: an expired refresh token is rejected, and a missing cookie is rejected.
const request = require("supertest");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");

let mongo;
let app;
let User;
let RefreshToken;
let issueRefreshToken;
let hashToken;

const TOKEN_SECRET = "test_token_secret";
const ACCESS_TOKEN_LIFETIME_SECONDS = 15 * 60;

const cookieHeader = (rawToken) => `refreshToken=${rawToken}`;
const setCookieFor = (response) =>
  (response.headers["set-cookie"] || []).find((c) =>
    c.startsWith("refreshToken="),
  ) || null;

const createUser = () =>
  User.create({
    name: "Test User",
    email: "test@example.com",
    password: "not-a-real-hash",
    verify: true,
  });

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();

  // These must be set BEFORE requiring the app: config/keys.js and services/passport.js
  // read configuration at require time, and passport throws without a clientID.
  process.env.NODE_ENV = "test";
  process.env.MONGO_URI = mongo.getUri();
  process.env.TOKEN_SECRET = TOKEN_SECRET;
  process.env.COOKIE_KEY = "test_cookie_key";
  process.env.GOOGLE_CLIENT = "test-google-client-id";
  process.env.GOOGLE_SECRET = "test-google-client-secret";

  await mongoose.connect(process.env.MONGO_URI);

  app = require("../app");
  User = require("../models/User");
  RefreshToken = require("../models/RefreshToken");
  ({ issueRefreshToken, hashToken } = require("../helper/refreshToken"));
});

afterEach(async () => {
  const collections = await mongoose.connection.db.collections();
  for (const collection of collections) {
    await collection.deleteMany({});
  }
});

afterAll(async () => {
  await mongoose.disconnect();
  if (mongo) await mongo.stop();
});

describe("[CWE-613] access token lifetime", () => {
  it("returns 401 with TOKEN_EXPIRED for an expired access token", async () => {
    const user = await createUser();
    const expiredToken = jwt.sign({ id: user._id.toString() }, TOKEN_SECRET, {
      expiresIn: "-10s",
    });

    const res = await request(app)
      .put("/uploadprofile")
      .set("Authorization", `Bearer ${expiredToken}`)
      .send({ picture: "pic", about: "about" });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("TOKEN_EXPIRED");
  });

  it("returns 401 when the Authorization header is missing", async () => {
    const res = await request(app)
      .put("/uploadprofile")
      .send({ picture: "pic", about: "about" });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("TOKEN_MISSING");
  });
});

describe("[CWE-613] refresh token rotation", () => {
  it("mints a new 15m access token and rotates the refresh cookie", async () => {
    const user = await createUser();
    const { rawToken } = await issueRefreshToken(user._id);

    const res = await request(app)
      .post("/auth/refresh")
      .set("Cookie", [cookieHeader(rawToken)]);

    expect(res.status).toBe(200);
    expect(res.body.id).toBe(user._id.toString());

    const decoded = jwt.verify(res.body.token, TOKEN_SECRET);
    expect(decoded.id).toBe(user._id.toString());
    // The fix: 15 minutes, not the previous 15 days.
    expect(decoded.exp - decoded.iat).toBe(ACCESS_TOKEN_LIFETIME_SECONDS);

    const newCookie = setCookieFor(res);
    expect(newCookie).toBeTruthy();
    expect(newCookie).not.toBe(cookieHeader(rawToken));
    // The refresh token must be unreadable by JavaScript.
    expect(newCookie).toMatch(/HttpOnly/i);
  });

  it("rejects reuse of an already rotated refresh token and revokes all sessions", async () => {
    const user = await createUser();
    const first = await issueRefreshToken(user._id);

    const exchange = await request(app)
      .post("/auth/refresh")
      .set("Cookie", [cookieHeader(first.rawToken)]);
    expect(exchange.status).toBe(200);

    // Replaying the consumed token is treated as theft.
    const replay = await request(app)
      .post("/auth/refresh")
      .set("Cookie", [cookieHeader(first.rawToken)]);
    expect(replay.status).toBe(401);
    expect(replay.body.code).toBe("REFRESH_TOKEN_INVALID");

    const stillActive = await RefreshToken.countDocuments({
      userId: user._id,
      revokedAt: null,
    });
    expect(stillActive).toBe(0);
  });

  it("rejects an expired refresh token", async () => {
    const user = await createUser();
    const rawToken = "a".repeat(128);
    await RefreshToken.create({
      userId: user._id,
      tokenHash: hashToken(rawToken),
      expiresAt: new Date(Date.now() - 1000),
    });

    const res = await request(app)
      .post("/auth/refresh")
      .set("Cookie", [cookieHeader(rawToken)]);

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("REFRESH_TOKEN_INVALID");
  });

  it("rejects a refresh request with no cookie", async () => {
    const res = await request(app).post("/auth/refresh");

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("REFRESH_TOKEN_INVALID");
  });
});
