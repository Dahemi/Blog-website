// [CWE-640] Regression tests for the password-reset flow rewrite.
//
// The threat: changePassword accepted `{ email, password }` with no authentication, no code
// check and no ticket, so any anonymous caller could overwrite any account's password. It
// now requires a short-lived, single-use, purpose-scoped ticket whose signed `userId` claim
// decides whose password changes.
//
// Required by the brief: no ticket -> 401, wrong purpose -> 401, reused -> 401,
// expired -> 401.
jest.mock("../helper/mail");

const request = require("supertest");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");

let mongo;
let app;
let User;
let Code;
let issueResetTicket;
let issueRefreshToken;

const TOKEN_SECRET = "test_token_secret";
// Passes V15's policy: 12+ chars, under 72 bytes, high zxcvbn score.
const STRONG = "q7Zx!2vLm9#Rt4Wp8Ks6Df";

const makeUser = (name, email, password = "original-password-hash") =>
  User.create({ name, email, password, verify: true });

const signTicket = (payload, options) =>
  jwt.sign(payload, TOKEN_SECRET, options);

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();

  process.env.NODE_ENV = "test";
  process.env.MONGO_URI = mongo.getUri();
  process.env.TOKEN_SECRET = TOKEN_SECRET;
  process.env.COOKIE_KEY = "test_cookie_key";
  process.env.GOOGLE_CLIENT = "test-google-client-id";
  process.env.GOOGLE_SECRET = "test-google-secret";

  await mongoose.connect(process.env.MONGO_URI);

  app = require("../app");
  User = require("../models/User");
  Code = require("../models/Code");
  ({ issueResetTicket } = require("../helper/resetTicket"));
  ({ issueRefreshToken } = require("../helper/refreshToken"));
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

describe("[CWE-640] changePassword requires a valid reset ticket", () => {
  it("rejects a request with no ticket at all (401)", async () => {
    const user = await makeUser("Victim", "victim@example.com");

    const res = await request(app)
      .post("/changePassword")
      .send({ newPassword: STRONG });

    expect(res.status).toBe(401);
    const after = await User.findById(user._id);
    expect(after.password).toBe("original-password-hash");
  });

  it("rejects the OLD { email, password } contract (401)", async () => {
    // This is the core of the vulnerability: naming an account must no longer be enough.
    const user = await makeUser("Victim", "victim@example.com");

    const res = await request(app)
      .post("/changePassword")
      .send({ email: user.email, password: STRONG });

    expect(res.status).toBe(401);
    const after = await User.findById(user._id);
    expect(after.password).toBe("original-password-hash");
  });

  it("rejects a ticket signed for a different purpose (401)", async () => {
    const user = await makeUser("Victim", "victim@example.com");
    // Correctly signed with the server secret, but not a password-reset ticket.
    const wrongPurpose = signTicket(
      { userId: user._id.toString(), purpose: "email-verify", jti: "some-jti" },
      { expiresIn: "5m" },
    );

    const res = await request(app)
      .post("/changePassword")
      .send({ resetTicket: wrongPurpose, newPassword: STRONG });

    expect(res.status).toBe(401);
    const after = await User.findById(user._id);
    expect(after.password).toBe("original-password-hash");
  });

  it("rejects an expired ticket (401)", async () => {
    const user = await makeUser("Victim", "victim@example.com");
    const expired = signTicket(
      {
        userId: user._id.toString(),
        purpose: "password-reset",
        jti: "expired-jti",
      },
      { expiresIn: "-1s" },
    );

    const res = await request(app)
      .post("/changePassword")
      .send({ resetTicket: expired, newPassword: STRONG });

    expect(res.status).toBe(401);
  });

  it("rejects a ticket whose signature was forged with the wrong key (401)", async () => {
    const user = await makeUser("Victim", "victim@example.com");
    const forged = jwt.sign(
      {
        userId: user._id.toString(),
        purpose: "password-reset",
        jti: "forged-jti",
      },
      "not-the-real-secret",
      { expiresIn: "5m" },
    );

    const res = await request(app)
      .post("/changePassword")
      .send({ resetTicket: forged, newPassword: STRONG });

    expect(res.status).toBe(401);
  });

  it("rejects a valid-signature ticket whose jti was never issued (401)", async () => {
    // Guards the server-side single-use record, not just the signature.
    const user = await makeUser("Victim", "victim@example.com");
    const unrecorded = signTicket(
      {
        userId: user._id.toString(),
        purpose: "password-reset",
        jti: "never-issued",
      },
      { expiresIn: "5m" },
    );

    const res = await request(app)
      .post("/changePassword")
      .send({ resetTicket: unrecorded, newPassword: STRONG });

    expect(res.status).toBe(401);
  });
});

describe("[CWE-640] tickets are single-use", () => {
  it("accepts the first use and rejects the replay (401)", async () => {
    const user = await makeUser("Victim", "victim@example.com");
    const ticket = await issueResetTicket(user._id);

    const first = await request(app)
      .post("/changePassword")
      .send({ resetTicket: ticket, newPassword: STRONG });
    expect(first.status).toBe(200);

    const after = await User.findById(user._id);
    expect(await bcrypt.compare(STRONG, after.password)).toBe(true);

    const replay = await request(app)
      .post("/changePassword")
      .send({ resetTicket: ticket, newPassword: "AnotherStr0ng!Passphrase42" });

    expect(replay.status).toBe(401);
    // The replay must not have changed anything.
    const stillFirst = await User.findById(user._id);
    expect(await bcrypt.compare(STRONG, stillFirst.password)).toBe(true);
  });

  it("does NOT burn the ticket when the new password fails policy", async () => {
    // Verifying and consuming are separate steps on purpose: a rejected password must be
    // retryable, otherwise a typo would force the user to restart the whole reset flow.
    const user = await makeUser("Victim", "victim@example.com");
    const ticket = await issueResetTicket(user._id);

    const weak = await request(app)
      .post("/changePassword")
      .send({ resetTicket: ticket, newPassword: "aaaaaaaaaaaa" });
    expect(weak.status).toBe(400);

    const retry = await request(app)
      .post("/changePassword")
      .send({ resetTicket: ticket, newPassword: STRONG });
    expect(retry.status).toBe(200);
  });
});

describe("[CWE-640] the target user comes from the ticket, not the body", () => {
  it("ignores an email in the body and only changes the ticket's user", async () => {
    const victim = await makeUser("Victim", "victim@example.com");
    const attacker = await makeUser("Attacker", "attacker@example.com");

    // The attacker holds a legitimate ticket for THEIR OWN account...
    const ticket = await issueResetTicket(attacker._id);

    // ...and tries to point it at the victim by adding an email to the body.
    const res = await request(app)
      .post("/changePassword")
      .send({ resetTicket: ticket, newPassword: STRONG, email: victim.email });

    expect(res.status).toBe(200);

    const victimAfter = await User.findById(victim._id);
    expect(victimAfter.password).toBe("original-password-hash");

    const attackerAfter = await User.findById(attacker._id);
    expect(await bcrypt.compare(STRONG, attackerAfter.password)).toBe(true);
  });
});

describe("[CWE-640] reset code flow mints a working ticket", () => {
  it("validateResetCode returns a ticket that changePassword accepts", async () => {
    const user = await makeUser("Victim", "victim@example.com");
    await Code.create({ code: "13579", user: user._id });

    const validated = await request(app)
      .post("/validateResetCode")
      .send({ email: user.email, code: "13579" });

    expect(validated.status).toBe(200);
    expect(validated.body.message).toBe("ok");
    expect(typeof validated.body.resetTicket).toBe("string");

    const changed = await request(app)
      .post("/changePassword")
      .send({ resetTicket: validated.body.resetTicket, newPassword: STRONG });

    expect(changed.status).toBe(200);
    const after = await User.findById(user._id);
    expect(await bcrypt.compare(STRONG, after.password)).toBe(true);
  });

  it("makes the emailed code single-use (cannot mint a second ticket)", async () => {
    const user = await makeUser("Victim", "victim@example.com");
    await Code.create({ code: "13579", user: user._id });

    const first = await request(app)
      .post("/validateResetCode")
      .send({ email: user.email, code: "13579" });
    expect(first.status).toBe(200);

    const second = await request(app)
      .post("/validateResetCode")
      .send({ email: user.email, code: "13579" });
    expect(second.status).toBe(400);
  });
});

describe("[CWE-640] the reset flow no longer enumerates accounts", () => {
  it("returns an identical response for a registered and an unregistered email", async () => {
    await makeUser("Known", "known@example.com");

    // Before the fix this 500'd for the unknown address (null dereference) and 200'd for
    // the known one — the status code alone revealed whether an account existed.
    const known = await request(app)
      .post("/sendResetPasswordCode")
      .send({ email: "known@example.com" });
    const unknown = await request(app)
      .post("/sendResetPasswordCode")
      .send({ email: "nobody@example.com" });

    expect(unknown.status).toBe(known.status);
    expect(unknown.body).toEqual(known.body);
  });

  it("returns the same failure for an unknown email and a wrong code", async () => {
    const user = await makeUser("Known", "known@example.com");
    await Code.create({ code: "13579", user: user._id });

    const wrongCode = await request(app)
      .post("/validateResetCode")
      .send({ email: user.email, code: "00000" });
    const noSuchUser = await request(app)
      .post("/validateResetCode")
      .send({ email: "nobody@example.com", code: "00000" });

    expect(noSuchUser.status).toBe(wrongCode.status);
    expect(noSuchUser.body).toEqual(wrongCode.body);
  });
});

describe("[CWE-613] a password reset ends existing sessions", () => {
  it("revokes the user's refresh tokens", async () => {
    // This was the item the V12 task deferred to V1.
    const user = await makeUser("Victim", "victim@example.com");
    const { rawToken } = await issueRefreshToken(user._id);

    const before = await request(app)
      .post("/auth/refresh")
      .set("Cookie", [`refreshToken=${rawToken}`]);
    expect(before.status).toBe(200);

    // Issue a fresh refresh token, then reset the password through a ticket.
    const { rawToken: live } = await issueRefreshToken(user._id);
    const ticket = await issueResetTicket(user._id);
    const changed = await request(app)
      .post("/changePassword")
      .send({ resetTicket: ticket, newPassword: STRONG });
    expect(changed.status).toBe(200);

    const after = await request(app)
      .post("/auth/refresh")
      .set("Cookie", [`refreshToken=${live}`]);
    expect(after.status).toBe(401);
  });
});
