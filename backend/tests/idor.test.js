// [CWE-639] Regression tests for the IDOR / owner-check fix.
//
// The threat: a route trusted a user id supplied in the request body, so any caller could
// read or mutate another user's data by naming that user. These tests prove that
//   (a) every user-owned route now requires a token, and
//   (b) when a caller supplies somebody else's id, the operation is still applied to the
//       authenticated caller (or rejected), never to the named victim.
jest.mock("../helper/reportmail", () => ({ sendReportMail: jest.fn() }));

const request = require("supertest");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");

let mongo;
let app;
let User;
let Post;
let generateToken;

const TOKEN_SECRET = "test_token_secret";

// likeslist/bookmarkslist are Maps that the bookmark/like controllers call .set() on, so a
// user without them would throw. register() seeds them, so mirror that here.
const makeUser = (name, email) =>
  User.create({
    name,
    email,
    password: "not-a-real-hash",
    verify: true,
    likeslist: {},
    bookmarkslist: {},
  });

const makePost = (userId, title) =>
  Post.create({
    title,
    description: "description",
    category: "tech",
    image: "image",
    user: userId,
    content: "content",
  });

// Seed fields on a user with a load-then-save so Mongoose's version key stays in sync.
// Seeding with findByIdAndUpdate drifts the version key and makes later controller saves
// throw a VersionError.
const seedUser = async (userId, fields) => {
  const doc = await User.findById(userId);
  Object.assign(doc, fields);
  await doc.save();
  return doc;
};

const auth = (token) => ["Authorization", `Bearer ${token}`];
const ids = (arr) => (arr || []).map((v) => String(v));

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();

  // Must be set before requiring the app: config/keys.js and the passport setup read their
  // configuration at require time.
  process.env.NODE_ENV = "test";
  process.env.MONGO_URI = mongo.getUri();
  process.env.TOKEN_SECRET = TOKEN_SECRET;
  process.env.COOKIE_KEY = "test_cookie_key";
  process.env.GOOGLE_CLIENT = "test-google-client-id";
  process.env.GOOGLE_SECRET = "test-google-secret";

  await mongoose.connect(process.env.MONGO_URI);

  app = require("../app");
  User = require("../models/User");
  Post = require("../models/Post");
  ({ generateToken } = require("../helper/token"));
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

// Every route that acts on user-owned data.
const PROTECTED_ROUTES = [
  ["post", "/setbookmark"],
  ["post", "/deletebookmark"],
  ["post", "/checkbookmark"],
  ["post", "/showbookmarks"],
  ["post", "/setlikes"],
  ["post", "/deletelikes"],
  ["post", "/checklikes"],
  ["post", "/getallLikes"],
  ["post", "/getallBookmarks"],
  ["post", "/showLikemarks"],
  ["post", "/deletepost"],
  ["post", "/showmyposts"],
  ["post", "/changeabout"],
  ["post", "/startfollow"],
  ["post", "/unfollow"],
  ["post", "/checkfollow"],
  ["post", "/fetchfollowing"],
  ["post", "/reportcontent"],
];

describe("[CWE-639] user-owned routes require authentication", () => {
  it.each(PROTECTED_ROUTES)(
    "rejects unauthenticated %s %s with 401",
    async (method, path) => {
      const res = await request(app)[method](path).send({});
      expect(res.status).toBe(401);
    },
  );
});

describe("[CWE-639] the actor is taken from the token, not the body", () => {
  let victim;
  let attacker;
  let attackerToken;
  let victimPost;

  beforeEach(async () => {
    victim = await makeUser("Victim", "victim@example.com");
    attacker = await makeUser("Attacker", "attacker@example.com");
    attackerToken = generateToken({ id: attacker._id.toString() });
    victimPost = await makePost(victim._id, "victim post");
  });

  it("setbookmark bookmarks for the caller, not the userid in the body", async () => {
    await request(app)
      .post("/setbookmark")
      .set(...auth(attackerToken))
      .send({
        postid: victimPost._id.toString(),
        userid: victim._id.toString(),
      });

    const victimAfter = await User.findById(victim._id);
    const attackerAfter = await User.findById(attacker._id);

    expect(ids(victimAfter.bookmarks)).not.toContain(victimPost._id.toString());
    expect(ids(attackerAfter.bookmarks)).toContain(victimPost._id.toString());
  });

  it("deletebookmark cannot remove another user's bookmark", async () => {
    await seedUser(victim._id, { bookmarks: [victimPost._id] });

    await request(app)
      .post("/deletebookmark")
      .set(...auth(attackerToken))
      .send({
        postid: victimPost._id.toString(),
        userid: victim._id.toString(),
      });

    const victimAfter = await User.findById(victim._id);
    expect(ids(victimAfter.bookmarks)).toContain(victimPost._id.toString());
  });

  it("setlikes records the like against the caller", async () => {
    await request(app)
      .post("/setlikes")
      .set(...auth(attackerToken))
      .send({
        postid: victimPost._id.toString(),
        userid: victim._id.toString(),
      });

    const victimAfter = await User.findById(victim._id);
    const attackerAfter = await User.findById(attacker._id);

    expect(ids(victimAfter.likes)).not.toContain(victimPost._id.toString());
    expect(ids(attackerAfter.likes)).toContain(victimPost._id.toString());
  });

  it("deletelikes cannot remove another user's like", async () => {
    await seedUser(victim._id, { likes: [victimPost._id] });

    await request(app)
      .post("/deletelikes")
      .set(...auth(attackerToken))
      .send({
        postid: victimPost._id.toString(),
        userid: victim._id.toString(),
      });

    const victimAfter = await User.findById(victim._id);
    expect(ids(victimAfter.likes)).toContain(victimPost._id.toString());
  });

  it("getallBookmarks cannot read another user's bookmarks", async () => {
    await seedUser(victim._id, { bookmarks: [victimPost._id] });

    const res = await request(app)
      .post("/getallBookmarks")
      .set(...auth(attackerToken))
      .send({ userid: victim._id.toString() });

    expect(res.status).toBe(201);
    expect(ids(res.body)).not.toContain(victimPost._id.toString());
  });

  it("getallLikes cannot read another user's likes", async () => {
    await seedUser(victim._id, { likes: [victimPost._id] });

    const res = await request(app)
      .post("/getallLikes")
      .set(...auth(attackerToken))
      .send({ userid: victim._id.toString() });

    expect(res.status).toBe(201);
    expect(ids(res.body)).not.toContain(victimPost._id.toString());
  });

  it("showbookmarks cannot read another user's bookmarks", async () => {
    await seedUser(victim._id, { bookmarks: [victimPost._id] });

    const res = await request(app)
      .post("/showbookmarks")
      .set(...auth(attackerToken))
      .send({ id: victim._id.toString() });

    const titles = (res.body.msg || []).map((p) => p.title);
    expect(titles).not.toContain("victim post");
  });

  it("changeabout edits the caller, not the id in the body", async () => {
    await request(app)
      .post("/changeabout")
      .set(...auth(attackerToken))
      .send({ about: "pwned", id: victim._id.toString() });

    const victimAfter = await User.findById(victim._id);
    const attackerAfter = await User.findById(attacker._id);

    expect(victimAfter.about).not.toBe("pwned");
    expect(attackerAfter.about).toBe("pwned");
  });

  it("startfollow makes the caller follow the target, not the body actor", async () => {
    const third = await makeUser("Third", "third@example.com");

    await request(app)
      .post("/startfollow")
      .set(...auth(attackerToken))
      .send({ id: victim._id.toString(), id2: third._id.toString() });

    const victimAfter = await User.findById(victim._id);
    const attackerAfter = await User.findById(attacker._id);

    expect(ids(victimAfter.following)).not.toContain(third._id.toString());
    expect(ids(attackerAfter.following)).toContain(third._id.toString());
  });

  it("unfollow cannot unfollow on behalf of another user", async () => {
    const third = await makeUser("Third", "third@example.com");
    await seedUser(victim._id, { following: [third._id] });

    await request(app)
      .post("/unfollow")
      .set(...auth(attackerToken))
      .send({ id: victim._id.toString(), id2: third._id.toString() });

    const victimAfter = await User.findById(victim._id);
    expect(ids(victimAfter.following)).toContain(third._id.toString());
  });

  it("fetchfollowing returns the caller's list, not the id in the body", async () => {
    const third = await makeUser("Third", "third@example.com");
    await seedUser(victim._id, { following: [third._id] });

    const res = await request(app)
      .post("/fetchfollowing")
      .set(...auth(attackerToken))
      .send({ id: victim._id.toString() });

    expect(res.status).toBe(200);
    const pids = (res.body.msg || []).map((f) => String(f.pid));
    expect(pids).not.toContain(third._id.toString());
  });
});

describe("[CWE-639] deletepost enforces ownership on the post itself", () => {
  let victim;
  let attacker;
  let attackerToken;

  beforeEach(async () => {
    victim = await makeUser("Victim", "victim@example.com");
    attacker = await makeUser("Attacker", "attacker@example.com");
    attackerToken = generateToken({ id: attacker._id.toString() });
  });

  it("refuses to delete a post owned by someone else", async () => {
    const victimPost = await makePost(victim._id, "victim post");

    const res = await request(app)
      .post("/deletepost")
      .set(...auth(attackerToken))
      .send({
        postid: victimPost._id.toString(),
        userid: victim._id.toString(),
      });

    expect(res.status).toBe(403);
    // The post document must survive. Deriving the actor from the token alone was not
    // enough here: the old code deleted the post by id with no owner check at all.
    expect(await Post.findById(victimPost._id)).not.toBeNull();
  });

  it("still allows the owner to delete their own post", async () => {
    const ownPost = await makePost(attacker._id, "attacker post");
    await seedUser(attacker._id, { posts: [ownPost._id] });

    const res = await request(app)
      .post("/deletepost")
      .set(...auth(attackerToken))
      .send({ postid: ownPost._id.toString() });

    expect(res.status).toBe(200);
    expect(await Post.findById(ownPost._id)).toBeNull();
  });
});

describe("[CWE-639] deliberately public profile reads are not over-protected", () => {
  // These read ANOTHER user's public profile data and are called from the public article
  // page. Adding auth here would break logged-out browsing, so they must stay open.
  it("fetchprof, countfollower, countfollowing and getUser work without a token", async () => {
    const user = await makeUser("Public", "public@example.com");

    expect(
      (await request(app).post("/fetchprof").send({ id: user._id.toString() }))
        .status,
    ).toBe(200);
    expect(
      (
        await request(app)
          .post("/countfollower")
          .send({ id: user._id.toString() })
      ).status,
    ).toBe(200);
    expect(
      (
        await request(app)
          .post("/countfollowing")
          .send({ id: user._id.toString() })
      ).status,
    ).toBe(200);
    expect(
      (await request(app).get(`/getUser/${user._id.toString()}`)).status,
    ).toBe(200);
  });
});
