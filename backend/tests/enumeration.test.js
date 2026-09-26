// V5 — user enumeration (CWE-204) regression tests.
//
// The threat: an unauthenticated caller could test any email address and learn
// whether it had an account, and which auth method it used, from three sources:
//   1. POST /login returned three distinguishable messages
//      ("the email you entered is not registered." / "You have account associated
//       with google..." / "Invalid Credentials. Please Try Again.")
//   2. POST /login only ran bcrypt.compare when the account existed, so the
//      response time answered the question even if the message did not (CWE-208).
//   3. POST /findOutUser existed solely to answer it — 200 with the user object,
//      404 when unknown.
//
// These tests assert on the FULL serialised response (status + body), because the
// defence is that the branches are indistinguishable, not merely that each is a 400.

const fs = require("fs");
const path = require("path");
const express = require("express");
const request = require("supertest");
const bcrypt = require("bcrypt");

// Mock the model so no real MongoDB is needed (mirrors login.injection.test.js).
jest.mock("../models/User", () => ({
  findOne: jest.fn(),
}));
jest.mock("../helper/refreshToken", () => ({
  issueRefreshToken: jest.fn().mockResolvedValue({ rawToken: "raw" }),
  setRefreshCookie: jest.fn(),
  revokeAllForUser: jest.fn(),
}));

const User = require("../models/User");
const { login } = require("../controllers/user");

function makeApp() {
  const app = express();
  app.use(express.json());
  app.post("/login", login);
  return app;
}

const app = makeApp();

// A real bcrypt hash of "CorrectHorseBattery12" at the policy cost.
const KNOWN_HASH = bcrypt.hashSync("CorrectHorseBattery12", 12);

const post = (body) => request(app).post("/login").send(body);

// Status + raw body text — the whole observable response.
const fingerprint = (res) => `${res.status} ${res.text}`;

beforeEach(() => {
  jest.clearAllMocks();
});

describe("[CWE-204] POST /login is indistinguishable across failure modes", () => {
  it("unknown email and wrong password produce byte-identical responses", async () => {
    User.findOne.mockResolvedValue(null);
    const unknown = await post({
      temail: "nobody@example.com",
      password: "CorrectHorseBattery12",
    });

    User.findOne.mockResolvedValue({
      _id: "u1",
      email: "real@example.com",
      password: KNOWN_HASH,
      verify: true,
    });
    const wrongPassword = await post({
      temail: "real@example.com",
      password: "NotThePassword123",
    });

    expect(fingerprint(unknown)).toBe(fingerprint(wrongPassword));
    expect(unknown.status).toBe(400);
  });

  it("a Google-linked account is indistinguishable from an unknown address", async () => {
    User.findOne.mockResolvedValue(null);
    const unknown = await post({
      temail: "nobody@example.com",
      password: "AnyPassword123x",
    });

    User.findOne.mockResolvedValue({
      _id: "u2",
      email: "google@example.com",
      googleId: "1234567890",
      verify: true,
    });
    const googleAccount = await post({
      temail: "google@example.com",
      password: "AnyPassword123x",
    });

    expect(fingerprint(googleAccount)).toBe(fingerprint(unknown));
  });

  it("no failure response names the email, the account or the auth method", async () => {
    User.findOne.mockResolvedValue(null);
    const res = await post({
      temail: "nobody@example.com",
      password: "AnyPassword123x",
    });

    expect(res.body.message).toBe("Invalid email or password.");
    expect(res.text).not.toMatch(/not registered/i);
    expect(res.text).not.toMatch(/google/i);
    expect(res.text).not.toMatch(/invalid credentials/i);
    expect(res.text).not.toContain("nobody@example.com");
  });

  it("a correct password still authenticates (the fix is not a blanket denial)", async () => {
    User.findOne.mockResolvedValue({
      _id: "u3",
      email: "real@example.com",
      name: "Real User",
      password: KNOWN_HASH,
      verify: true,
      bookmarks: [],
      likes: [],
    });

    const res = await post({
      temail: "real@example.com",
      password: "CorrectHorseBattery12",
    });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
  });
});

describe("[CWE-208] POST /login does not leak existence through timing", () => {
  it("performs a bcrypt comparison even when the account does not exist", async () => {
    const spy = jest.spyOn(bcrypt, "compare");
    User.findOne.mockResolvedValue(null);

    await post({ temail: "nobody@example.com", password: "AnyPassword123x" });

    // Without the dummy-hash compare this is 0 — the unknown-email path would
    // return in ~2ms while a real account costs ~250ms at cost 12.
    expect(spy).toHaveBeenCalledTimes(1);
    const [, hash] = spy.mock.calls[0];
    expect(hash).toMatch(/^\$2[aby]\$12\$/); // same algorithm and cost as live hashes
    spy.mockRestore();
  });

  it("performs a bcrypt comparison for a Google-linked account too", async () => {
    const spy = jest.spyOn(bcrypt, "compare");
    User.findOne.mockResolvedValue({
      _id: "u4",
      email: "google@example.com",
      googleId: "1234567890",
    });

    await post({ temail: "google@example.com", password: "AnyPassword123x" });

    // This branch has no stored hash at all, so it must use the dummy.
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });

  it("unknown and known addresses take comparable time", async () => {
    User.findOne.mockResolvedValue(null);
    const t0 = Date.now();
    await post({ temail: "nobody@example.com", password: "AnyPassword123x" });
    const unknownMs = Date.now() - t0;

    User.findOne.mockResolvedValue({
      _id: "u5",
      email: "real@example.com",
      password: KNOWN_HASH,
      verify: true,
    });
    const t1 = Date.now();
    await post({ temail: "real@example.com", password: "NotThePassword123" });
    const knownMs = Date.now() - t1;

    // Deliberately loose: this asserts the same order of magnitude, not equality.
    // A tight bound would be flaky on shared CI. Pre-fix the ratio was ~100x.
    const ratio = Math.max(unknownMs, knownMs) / Math.max(1, Math.min(unknownMs, knownMs));
    expect(ratio).toBeLessThan(5);
  });
});

describe("[CWE-204] the /findOutUser enumeration endpoint is gone", () => {
  it("no longer exists as a controller export", () => {
    const controllers = require("../controllers/user");
    expect(controllers.findOutUser).toBeUndefined();
  });

  it("is no longer registered as a route", () => {
    const routes = fs.readFileSync(
      path.join(__dirname, "..", "routes", "user.js"),
      "utf8",
    );
    expect(routes).not.toMatch(/router\.\w+\(\s*["']\/findOutUser["']/);
  });

  it("is no longer called by the password-reset page", () => {
    const page = fs.readFileSync(
      path.join(__dirname, "..", "..", "client", "src", "pages", "ResetPassword.js"),
      "utf8",
    );
    // The string may still appear in an explanatory comment; what must be gone is
    // any request to it.
    expect(page).not.toMatch(/axios\.post\([^)]*findOutUser/s);
  });
});

// Found while filming the demo: the server's uniform /login response was being bypassed
// entirely, because the login page asked /checkifverify first and branched on its answer.
// A uniform endpoint is worthless if the client queries a different one before it.
describe("[CWE-204] the /checkifverify pre-check oracle is gone", () => {
  it("is no longer exported by the verifyemail controller", () => {
    const controllers = require("../controllers/verifyemail");
    expect(controllers.checkifverify).toBeUndefined();
  });

  it("is no longer registered as a route", () => {
    const routes = fs.readFileSync(
      path.join(__dirname, "..", "routes", "user.js"),
      "utf8",
    );
    expect(routes).not.toMatch(/router\.\w+\(\s*["']\/checkifverify["']/);
  });

  it("the login page no longer pre-checks the address before submitting", () => {
    const page = fs.readFileSync(
      path.join(__dirname, "..", "..", "client", "src", "pages", "Auth.js"),
      "utf8",
    );
    // Neither the helper call nor the setError branches it drove may remain. Matched as
    // code rather than as bare strings, since the comment explaining the fix names them.
    expect(page).not.toMatch(/await\s+checkifverify\s*\(/);
    expect(page).not.toMatch(/setError\(\s*["'`]Please Sign Up First/);
    expect(page).not.toMatch(/setError\(\s*["'`]Please Sign up and Verify Your Email/);
  });

  it("the client helper that called it is gone", () => {
    const helpers = fs.readFileSync(
      path.join(__dirname, "..", "..", "client", "src", "helpers", "index.js"),
      "utf8",
    );
    expect(helpers).not.toMatch(/export const checkifverify/);
  });

  it("the verification flow's own endpoints are untouched", () => {
    // [V11] Registration and OTP verification must keep working — the fix removes the
    // existence oracle, not the verification feature.
    const controllers = require("../controllers/verifyemail");
    expect(typeof controllers.sendmail).toBe("function");
    expect(typeof controllers.checkotpv).toBe("function");
    expect(typeof controllers.verifycode).toBe("function");
  });
});

