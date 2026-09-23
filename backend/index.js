// [CWE-613] Refactor: this entrypoint now owns only process-level concerns (env, DB
// connection, port). The express app was extracted into ./app so that tests can import
// it with supertest without binding a port or opening a database connection.
const keys = require("./config/keys");
const mongoose = require("mongoose");
const app = require("./app");

const Port = keys.PORT || 5002;

mongoose.set("strictQuery", false);
mongoose.connect(keys.MONGO_URI);

app.listen(Port, () => {
  console.log(`server running ${Port}`);
});
