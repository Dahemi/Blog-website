// [CWE-613] Refactor: this entrypoint now owns only process-level concerns (env, DB
// connection, port). The express app was extracted into ./app so that tests can import
// it with supertest without binding a port or opening a database connection.
const keys = require("./config/keys");
const mongoose = require("mongoose");
const app = require("./app");

const Port = keys.PORT || 5002;

mongoose.set("strictQuery", false);
mongoose.connect(keys.MONGO_URI)

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));


app.set("trust proxy", 1)
const { globalLimiter } = require("./middleware/rateLimit");
app.use(globalLimiter);
app.use(cookieParser())
app.use(session({
  proxy: true,
  secret: keys.COOKIE_KEY,
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl: keys.MONGO_URI,
    collectionName: "mySessions",
  }),
  cookie: {
    maxAge: 15 * 24 * 60 * 60 * 1000, // Uncomment if needed for cookie lifespan
    sameSite: process.env.NODE_ENV === 'production' ? "none" : "lax", // "none" for cross-site cookies in production
    secure: process.env.NODE_ENV === 'production', // Secure should be true in production (HTTPS)
  },
}))

app.use(passport.initialize());
app.use(passport.session());

app.use(
  fileUpload({
    useTempFiles: true,
  })
);


app.use("/", userRoutes);
require("./servises/passport");
app.use("/", uploadRoutes);
app.use("/", postRoutes);
mongoose.connect(keys.MONGO_URI);

app.listen(Port, () => {
  console.log(`server running ${Port}`);
});
