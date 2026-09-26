const { model, Schema } = require("mongoose");
const userSchema = new Schema(
  {
    name: {
      type: String,
      // required: true,
    },
    email: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: function () { return !this.googleId },
    },
    verify: {
      type: Boolean,
      default: false
    },
    googleId: {
      type: String,
      required: function () { return !this.password },
      index: true,
      sparse: true,     // most users have no googleId; sparse keeps the index usable
      unique: true,     // one Google identity cannot map to two local accounts
    },
    // [OIDC] Disambiguates how an account authenticates, so changePassword can refuse
    // accounts with no local password, and Google-linked accounts are identifiable.
    authProvider: {
      type: String,
      enum: ["local", "google", "both"],
      default: "local",
    },
    picture: {
      type: String,
      trim: true,
      default:
        "https://res.cloudinary.com/dmhcnhtng/image/upload/v1643044376/avatars/default_pic_jeaybr.png",
    },
    about: {
      type: String
    },
    bookmarks: {
      type: Array,
      default: []
    },
    likes: {
      type: Array,
      default: []
    },
    posts: {
      type: Array,
      default: []
    },
    following: {
      type: Array,
      default: [],
    },
    followerscount: {
      type: Number,
      default: 0,
    },
    followingcount: {
      type: Number,
      default: 0,
    },
    likeslist: {
      type: Map,
      of: Boolean,
    },
    bookmarkslist: {
      type: Map,
      of: Boolean,
    }

  },
  { timestamps: true }
);

// [CWE-200] Defence in depth: strip credential material from every serialization
// of a User document, so that any res.json(userDoc) in the app is safe by default.
// The explicit DTO in helper/userDto.js remains the primary control.
userSchema.set("toJSON", {
  transform: function (doc, ret) {
    delete ret.password;
    delete ret.googleId;
    delete ret.__v;
    return ret;
  },
});

module.exports = model("User", userSchema);

