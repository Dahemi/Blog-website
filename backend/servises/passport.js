const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passport = require("passport");
const keys = require("../config/keys")
const User = require('../models/User');

passport.use(new GoogleStrategy({
  clientID: keys.GOOGLE_CLIENT_ID,
  clientSecret: keys.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback",
  scope: ["profile", "email"]
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      User.findOne({ email: profile.emails[0].value }).then((user) => {
        if (user && user.picture == "https://res.cloudinary.com/dmhcnhtng/image/upload/v1643044376/avatars/default_pic_jeaybr.png") {
          user.picture = profile.photos[0].value;;
        }
        if (user && !user.googleId) {
          user.googleId = profile.id;
          user.password = "crnkefn";
          return done(null, user);
        }
        if (user && !user.likeslist) {
          user.likeslist = {};
        }
        if (user && !user.bookmarkslist) {
          user.bookmarkslist = {};
        }
        if (user) user.save();
      }
      )
      User.findOne({ googleId: profile.id }).then((existingUser) => {
        if (existingUser) {
          return done(null, existingUser)
        } else {
          var url = profile.photos[0].value;
          new User({ googleId: profile.id, email: profile.emails[0].value, picture: url, name: profile.displayName,verify: true, likeslist: {}, bookmarkslist: {} }).save().then((user) => {
            return done(null, user)
            // done(null, user)
          });
        }
      })
    }
    catch (error) {
      // console.log(error)
    }
  }
));

// [CWE-200] Only the user id goes into the session. Previously the whole user
// document was serialized, so the bcrypt hash was persisted into the
// `mySessions` collection in MongoDB on every Google sign-in.
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// used to deserialize the user
passport.deserializeUser((id, done) => {
  User.findById(id)
    .select("-password")
    .then((user) => done(null, user))
    .catch((err) => done(err, null));
});
// passport.initialize();
// passport.session();
