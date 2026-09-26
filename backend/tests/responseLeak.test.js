// [CWE-200 / CWE-359] Regression tests for the V6 response-leak fix.
//
// The threat: GET /getUser/:userId returned the whole Mongoose document, so an
// unauthenticated caller received the target's bcrypt password hash and email.
// The bug was subtle -- `const { password, ...otherdata } = user` reads the
// hash through a prototype getter but copies only the document's own enumerable
// keys ($__ and _doc), and _doc still holds every field.
//
// These tests assert on the *raw response text*, not just on parsed keys, so a
// hash nested anywhere in the body still fails the test.
const request = require("supertest");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const { MongoMemoryServer } = require("mongodb-memory-server");

let mongo;
let app;
let User;

const PLAINTEXT = "sample123";

const makeUser = async () =>
  User.create({
    name: "Olawale Adeyawa",
    email: "serendipity.author@example.com",
    password: await bcrypt.hash(PLAINTEXT, 10),
    verify: true,
    about: "Writes about slow travel, type, and paying attention.",
    likeslist: {},
    bookmarkslist: {},
  });

// Walk a parsed body looking for a key anywhere in the tree.
const hasKeyDeep = (value, key) => {
  if (value === null || typeof value !== "object") return false;
  if (!Array.isArray(value) && Object.prototype.hasOwnProperty.call(value, key)) {
    return true;
  }
  return Object.values(value).some((v) => hasKeyDeep(v, key));
};

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();

  process.env.NODE_ENV = "test";
  process.env.MONGO_URI = mongo.getUri();
  process.env.TOKEN_SECRET = "test_token_secret";
  process.env.COOKIE_KEY = "test_cookie_key";
  process.env.GOOGLE_CLIENT = "test-google-client-id";
  process.env.GOOGLE_SECRET = "test-google-secret";

  await mongoose.connect(process.env.MONGO_URI);

  app = require("../app");
  User = require("../models/User");
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

describe("[CWE-200] GET /getUser/:userId does not leak credential material", () => {
  it("does not return the bcrypt hash anywhere in the response body", async () => {
    const user = await makeUser();

    const res = await request(app).get(`/getUser/${user._id}`);

    expect(res.status).toBe(200);
    expect(res.text).not.toContain("$2b$");
    expect(res.text).not.toContain(user.password);
    expect(hasKeyDeep(res.body, "password")).toBe(false);
  });

  it("does not expose Mongoose internals ($__ / _doc) to the client", async () => {
    const user = await makeUser();

    const res = await request(app).get(`/getUser/${user._id}`);

    expect(hasKeyDeep(res.body, "_doc")).toBe(false);
    expect(hasKeyDeep(res.body, "$__")).toBe(false);
  });

  it("does not leak the user's email address", async () => {
    const user = await makeUser();

    const res = await request(app).get(`/getUser/${user._id}`);

    expect(res.text).not.toContain("serendipity.author@example.com");
    expect(hasKeyDeep(res.body, "email")).toBe(false);
  });

  it("returns exactly the public profile allowlist", async () => {
    const user = await makeUser();

    const res = await request(app).get(`/getUser/${user._id}`);

    expect(Object.keys(res.body).sort()).toEqual(
      [
        "_id",
        "about",
        "createdAt",
        "followerscount",
        "followingcount",
        "name",
        "picture",
      ].sort(),
    );
    expect(res.body.name).toBe("Olawale Adeyawa");
  });

  it("returns 404, not 500, for a user id that does not exist", async () => {
    const res = await request(app).get(`/getUser/${new mongoose.Types.ObjectId()}`);

    expect(res.status).toBe(404);
  });
});

describe("[CWE-200] defence in depth", () => {
  it("User.toJSON strips the password from any serialized document", async () => {
    const user = await makeUser();

    const serialized = JSON.stringify(user);

    expect(serialized).not.toContain("$2b$");
    expect(JSON.parse(serialized).password).toBeUndefined();
  });

  it("passport serializes only the user id into the session, not the document", async () => {
    const user = await makeUser();
    const passport = require("passport");
    require("../servises/passport");

    const serialized = await new Promise((resolve, reject) =>
      passport.serializeUser(user, (err, value) =>
        err ? reject(err) : resolve(value),
      ),
    );

    expect(String(serialized)).toBe(String(user._id));
    expect(JSON.stringify(serialized)).not.toContain("$2b$");
  });
});
