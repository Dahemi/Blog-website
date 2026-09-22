// Test runner configuration for the backend regression suite.
// The auth/refresh tests spin up an in-memory MongoDB, which needs a generous timeout
// on first run because mongodb-memory-server may download a mongod binary.
module.exports = {
  testEnvironment: "node",
  testMatch: ["**/tests/**/*.test.js"],
  testTimeout: 60000,
};
