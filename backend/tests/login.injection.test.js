// V2 - NoSQL injection (CWE-943) regression tests for POST /login.
//
// Key idea: an injection payload with a wrong password ALSO returns 400 via
// the bcrypt path, so status alone proves nothing. The real assertion is that
// malicious (non-string) input is rejected BEFORE it reaches User.findOne.
// These tests fail on the pre-fix controller (which passed the object straight
// into findOne) and pass once validation short-circuits first.

const express = require("express");
const request = require("supertest");
const mongoSanitize = require("express-mongo-sanitize");

// Mock the model so no real MongoDB is needed.
jest.mock("../models/User", () => ({
  findOne: jest.fn(),
}));
const User = require("../models/User");
const { login } = require("../controllers/user");

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use(mongoSanitize()); // mirrors backend/index.js
  app.post("/login", login);
  return app;
}

const app = makeApp();

beforeEach(() => {
  jest.clearAllMocks();
});

describe("POST /login - NoSQL injection defense", () => {
  test("valid string credentials reach the DB lookup (normal flow works)", async () => {
    // Return a user with a bogus hash so bcrypt.compare fails -> 400, but the
    // point is that findOne IS reached for legitimate string input.
    User.findOne.mockResolvedValue({
      _id: "x",
      password: "$2b$10$invalidhashinvalidhashinvalidhashinvalidhashh",
    });
    const res = await request(app)
      .post("/login")
      .send({ temail: "real@example.com", password: "whatever" });
    expect(User.findOne).toHaveBeenCalledWith({ email: "real@example.com" });
    expect(res.status).toBe(400); // wrong password, but lookup happened
  });

  test("operator-object email ($ne) is rejected before the DB lookup", async () => {
    const res = await request(app)
      .post("/login")
      .send({ temail: { $ne: null }, password: "WRONG" });
    expect(res.status).toBe(400);
    expect(User.findOne).not.toHaveBeenCalled();
  });

  test("takeover attempt ($ne + any password) never returns a token", async () => {
    // Even if a user exists and bcrypt would pass, validation blocks it first.
    User.findOne.mockResolvedValue({ _id: "x", password: "hash" });
    const res = await request(app)
      .post("/login")
      .send({ temail: { $ne: null }, password: "sample123" });
    expect(res.status).toBe(400);
    expect(res.body).not.toHaveProperty("token");
    expect(User.findOne).not.toHaveBeenCalled();
  });

  test("numeric email (bypasses sanitizer, caught by zod) is rejected", async () => {
    const res = await request(app)
      .post("/login")
      .send({ temail: 12345, password: "WRONG" });
    expect(res.status).toBe(400);
    expect(User.findOne).not.toHaveBeenCalled();
  });

  test("array email is rejected before the DB lookup", async () => {
    const res = await request(app)
      .post("/login")
      .send({ temail: ["a", "b"], password: "WRONG" });
    expect(res.status).toBe(400);
    expect(User.findOne).not.toHaveBeenCalled();
  });

  test("missing password is rejected", async () => {
    const res = await request(app)
      .post("/login")
      .send({ temail: "real@example.com" });
    expect(res.status).toBe(400);
    expect(User.findOne).not.toHaveBeenCalled();
  });
});
