const { validateEmail, validateLength } = require("../helper/validation");
const { toPublicUser } = require("../helper/userDto");
const User = require("../models/User");
const Post = require("../models/Post");
const bcrypt = require("bcrypt");
const { generateToken } = require("../helper/token");
// [CWE-613] Fix: rotating refresh tokens replace the previous 15-day access JWT.
const {
  issueRefreshToken,
  setRefreshCookie,
  // [CWE-613] Fix: used to end every session for a user after a password change.
  revokeAllForUser,
} = require("../helper/refreshToken");
// [CWE-640] Fix: single-use, purpose-scoped tickets authorise a password change.
const {
  issueResetTicket,
  verifyResetTicket,
  consumeResetTicket,
} = require("../helper/resetTicket");
const Code = require("../models/Code");
const { sendResetCode } = require("../helper/mail");
const { sendReportMail } = require("../helper/reportmail");
const generateCode = require("../helper/gen_code");
const { loginSchema } = require("../validators/login.schema");
const { validatePassword, BCRYPT_COST } = require("../helper/passwordPolicy");
const Verify = require("../models/emailverify");
const { sendVerifyCode } = require("../helper/mailverifymail");

// [CWE-208] A throwaway bcrypt hash at the same cost as the live policy, compared
// against on the login paths where no real hash exists. Its plaintext is irrelevant --
// it is never expected to match; it exists only so that a failed login costs the same
// time whether or not the account exists. Generated at BCRYPT_COST (12); if the cost
// in helper/passwordPolicy.js changes, regenerate this so the paths stay balanced.
const DUMMY_HASH =
  "$2b$12$1cQ9Ja3i0eDEBVIJg/muhuKGy.na9UdnceTAKkjXRwvgseQlk6Vfm";



exports.sendreportmails = async (req, res) => {
  try {
    // [CWE-639] Fix: the reporter is the authenticated caller, not a body-supplied id, so a
    // report can no longer be filed against someone else's account.
    const { pid, postid, name1, name2, reason } = req.body;
    const userid = req.user.id;
    const reporter = await User.findById(userid);
    const reported = await User.findById(postid);
    var emailr = reporter.email;
    var emailrd = reported.email;
    var namer = reporter.name;
    var namerd = reported.name;
    try {
      sendReportMail(emailr, emailrd, namer, namerd, reason, pid);
    } catch (error) {
      // console.log("error in sending mails")
    }
    return res.status(200).json({ msg: "ok" });
  } catch (error) {
    // console.log(error);
    return res.status(400).json({ msg: "Bad Request" });
  }
};
exports.register = async (req, res) => {
  try {
    const { name, temail, password } = req.body;
    if (!validateLength(name, 6, 15)) {
      return res
        .status(400)
        .json({ message: "Enter name between 6 to 15 characters !" });
    }
    if (!validateEmail(temail)) {
      return res.status(400).json({ message: "Please enter a valid email !" });
    }

    const pwCheck = validatePassword(password, [name, temail]);
    if (!pwCheck.ok) {
      return res.status(400).json({ message: pwCheck.message });
    }

    const check = await User.findOne({ email: temail });
    if (check) {
      return res.status(400).json({
        message: "This email already exists,try again with a different email",
      });
    }

    const hashed_password = await bcrypt.hash(password, BCRYPT_COST);
    const user = await new User({
      name: name,
      email: temail,
      password: hashed_password,
      verify: false,
      likeslist:{},
      bookmarkslist:{},
    }).save();

    // Issue a verification code and email it. Account stays unverified and
    // NO token is returned until the user proves they own the email.
    const code = generateCode(6);
    const existing = await Verify.findOne({ mail: temail });
    if (existing) {
      existing.otp = code;
      await existing.save();
    } else {
      await Verify.create({ mail: temail, otp: code });
    }
    try {
      sendVerifyCode(temail, name, code);
    } catch (mailErr) {
      // Registration still succeeds; user can request a resend.
    }

    res.send({
      id: user._id,
      name: user.name,
      verify: false,
      message: "Register Success ! Please verify your email to continue.",
    });
    // [CWE-613] Fix: short-lived (15m default) access token plus a rotating refresh
    // cookie, instead of a hardcoded 15-day JWT that could not be revoked.
    const token = generateToken({ id: user._id.toString() });
    const { rawToken } = await issueRefreshToken(user._id);
    setRefreshCookie(res, rawToken);
    res.send({
      id: user._id,
      name: user.name,
      picture: user.picture,
      token: token,
      message: "Register Success !",
      likes: [],
      bookmarks: [],
    });
  } catch (error) {
    // console.log(error);
    return res.status(500).json({ message: error.message });
  }
};
exports.deletebookmark = async (req, res) => {
  try {
    // [CWE-639] Fix: the actor is taken from the verified JWT, not a body-supplied id, so a
    // caller can no longer delete another user's bookmark by passing their id.
    const { postid } = req.body;
    const userid = req.user.id;
    const user = await User.findOne({ _id: userid });
    if (!user) {
      return res.status(202).json({ msg: "Does not exist" });
    }
    var m = user.bookmarks;
    var f = 0;
    if (m.length == 0) {
      return res.status(202).json({ msg: "Does not exists" });
    } else {
      for (var i = 0; i < m.length; i++) {
        if (m[i] == postid) {
          f = 1;
          m.splice(i, 1);
        }
      }
      user.bookmarks = m;
      if (user.bookmarkslist) {
        if (user.bookmarkslist.has(`${postid}`)) {
          user.bookmarkslist.delete(`${postid}`);
        }
      }
      user.save();
      if (f == 1) {
        return res.status(202).json({ msg: "deleted" });
      } else {
        return res.status(202).json({ msg: "not found" });
      }
    }
  } catch (error) {
    // console.log(error);
    return res.status(401).json({ msg: "ERROR" });
  }
};
exports.deletelikes = async (req, res) => {
  try {
    // [CWE-639] Fix: actor derived from the verified JWT, not the request body.
    const { postid } = req.body;
    const userid = req.user.id;
    const user = await User.findOne({ _id: userid });
    var m = user.likes;
    var f = 0;
    if (m.length == 0) {
      return res.status(202).json({ msg: "Does not exists" });
    } else {
      for (var i = 0; i < m.length; i++) {
        if (m[i] == postid) {
          f = 1;
          m.splice(i, 1);
        }
      }
      user.likes = m;
      if (user.likeslist) {
        if (user.likeslist.has(`${postid}`)) {
          user.likeslist.delete(`${postid}`);
        }
      }
      user.save();
      if (f == 1) {
        return res.status(202).json({ msg: "deleted" });
      } else {
        return res.status(202).json({ msg: "not found" });
      }
    }
    // user.bookmarks.push(postid);
  } catch (error) {
    // console.log(error);
    return res.status(401).json({ msg: "ERROR" });
  }
};
exports.checklikes = async (req, res) => {
  try {
    // [CWE-639] Fix: actor derived from the verified JWT, not the request body.
    const { postid } = req.body;
    const userid = req.user.id;
    const user = await User.findOne({ _id: userid });
    var m = user.likes;
    if (m.length == 0) {
      return res.status(202).json({ msg: "Does not exist" });
    } else {
      if (user.likeslist) {
        if (user.likeslist.has(`${postid}`)) {
          return res.status(202).json({ msg: "ok" });
        }
      }
      for (var i = 0; i < m.length; i++) {
        if (m[i] == postid) {
          return res.status(202).json({ msg: "ok" });
        }
      }
      return res.status(202).json({ msg: "Does not exists" });
    }
    // user.bookmarks.push(postid);
  } catch (error) {
    // console.log(error);
    return res.status(401).json({ msg: "ERROR" });
  }
};
exports.getallLikes = async (req, res) => {
  try {
    // [CWE-639] Fix: previously returned any user's likes for an id taken from the body.
    const userid = req.user.id;
    const user = await User.findOne({ _id: userid }).select("likes");
    return res.status(201).json(user.likes);
  } catch (error) {
    // console.log(error);
    return res.status(401).json({ msg: "ERROR" });
  }
};
exports.getallBookmarks = async (req, res) => {
  try {
    // [CWE-639] Fix: previously returned any user's bookmarks for an id from the body.
    const userid = req.user.id;
    const user = await User.findOne({ _id: userid }).select("bookmarks");
    return res.status(201).json(user.bookmarks);
  } catch (error) {
    // console.log(error);
    return res.status(401).json({ msg: "ERROR" });
  }
};
exports.checkbookmark = async (req, res) => {
  try {
    // [CWE-639] Fix: actor derived from the verified JWT, not the request body.
    const { postid } = req.body;
    const userid = req.user.id;
    const user = await User.findOne({ _id: userid });
    // console.log(user);
    var m = user.bookmarks;
    if (m.length == 0) {
      return res.status(202).json({ msg: "Does not exist" });
    } else {
      if (user.bookmarkslist) {
        if (user.bookmarkslist.has(`${postid}`)) {
          return res.status(202).json({ msg: "ok" });
        }
      }
      for (var i = 0; i < m.length; i++) {
        if (m[i] == postid) {
          return res.status(202).json({ msg: "ok" });
        }
      }
      return res.status(202).json({ msg: "Does not exists" });
    }
    // user.bookmarks.push(postid);
  } catch (error) {
    // console.log(error);
    return res.status(401).json({ msg: "ERROR" });
  }
};
exports.fetchprof = async (req, res) => {
  try {
    const { id } = req.body;
    const data = await User.findById(id);
    const resp = {
      name: data.name,
      picture: data.picture,
      about: data.about,
      _id: id,
    };
    return res.status(200).json({ msg: resp });
  } catch (error) {
    // console.log(error)
    return res.status(400).json({ msg: "error" });
  }
};
exports.bookmark = async (req, res) => {
  try {
    // [CWE-639] Fix: the bookmark is written to the authenticated user's own account, so a
    // caller can no longer add a bookmark on behalf of somebody else.
    const { postid } = req.body;
    const userid = req.user.id;
    const user = await User.findOne({ _id: userid });
    var m = user.bookmarks;
    var f = 0;
    if (m.length == 0) {
      m.push(postid);
    } else {
      for (var i = 0; i < m.length; i++) {
        if (m[i] == postid) {
          f = 1;
          m.splice(i, 1);
          m.push(postid);
          break;
        }
      }
      if (f === 0) {
        m.push(postid);
      }
      user.bookmarks = m;
    }
    // [CWE-639] Fix: await the write. The save was fire-and-forget, so the response could be
    // sent before the bookmark persisted and any failure escaped the catch block silently.
    user.bookmarkslist.set(`${postid}`, true);
    await user.save();
    if (f == 1) {
      return res.status(202).json({ msg: "exists" });
    } else {
      return res.status(202).json({ msg: "ok" });
    }
  } catch (error) {
    // console.log(error);
    return res.status(401).json({ msg: "ERROR" });
  }
};
exports.likes = async (req, res) => {
  try {
    // [CWE-639] Fix: the like is recorded against the authenticated user, not a body id.
    const { postid } = req.body;
    const userid = req.user.id;
    var mt = await User.findOne({ _id: userid }).select("likes likeslist");
    var m = mt.likes;
    var f = 0;
    if (m.length == 0) {
      m.push(postid);
    } else {
      for (var i = 0; i < m.length; i++) {
        if (m[i] == postid) {
          f = 1;
          m.splice(i, 1);
          m.push(postid);
          break;
        }
      }
      if (f == 0) {
        m.push(postid);
      }
    }
    // [CWE-639] Fix: await the write so the like is committed before we respond, and so a
    // persistence failure is caught instead of becoming an unhandled rejection.
    mt.likes = m;
    mt.likeslist.set(`${postid}`, true);
    await mt.save();
    if (f == 1) {
      return res.status(202).json({ msg: "exists" });
    } else {
      return res.status(202).json({ msg: "ok" });
    }
  } catch (error) {
    // console.log(error);
    return res.status(401).json({ msg: "ERROR" });
  }
};
exports.showbookmark = async (req, res) => {
  try {
    // [CWE-639] Fix: returns the authenticated caller's own bookmarks only. Named `id` to
    // match the rest of the function, which declares `var userid` further down.
    const id = req.user.id;
    const data = await User.findById(id).select("bookmarks bookmarkslist");
    if (data.length == 0) {
      return res.status(200).json({ msg: [] });
    }
    var arr = data.bookmarks;
    var respon = [];
    var img = "";
    var title = "";
    var desc = "";
    var imgp = "";
    var name = "";
    var userid = "";
    var postid = "";
    var darr = [];
    for (var i = 0; i < arr.length; i++) {
      var pd = await Post.findById(arr[i]);
      if (!pd) {
        continue;
      }
      darr.push(arr[i]);
      img = pd.image;
      title = pd.title;
      desc = pd.description;
      userid = pd.user;
      var ud = await User.findById(userid);
      imgp = ud.picture;
      name = ud.name;
      _id = arr[i];
      const utcTimeString = pd.createdAt;
      const date = new Date(utcTimeString);
      respon.push({
        image: img,
        title: title,
        description: desc,
        user: {
          picture: imgp,
          name: name,
          _id: userid,
        },
        book: true,
        createdAt: date,
        _id: _id,
        views: pd.views,
      });
    }
    if (arr.length != darr.length) data.bookmarks = darr;
    await data.save();

    return res.status(200).json({ msg: respon });
  } catch (error) {
    // console.log(error)
    return res.status(400).json({ msg: "error" });
  }
};
exports.showLikemark = async (req, res) => {
  try {
    // [CWE-639] Fix: returns the authenticated caller's own liked posts only.
    const id = req.user.id;
    const data = await User.findById(id).select("likes");
    if (data.length == 0) {
      return res.status(200).json({ msg: [] });
    }
    var arr = data.likes;
    var respon = [];
    var img = "";
    var title = "";
    var desc = "";
    var imgp = "";
    var name = "";
    var userid = "";
    var postid = "";
    var darr = [];
    for (var i = 0; i < arr.length; i++) {
      var pd = await Post.findById(arr[i]);
      if (!pd) {
        continue;
      }
      darr.push(arr[i]);
      img = pd.image;
      title = pd.title;
      desc = pd.description;
      userid = pd.user;
      var ud = await User.findById(userid);
      imgp = ud.picture;
      name = ud.name;
      _id = arr[i];
      const utcTimeString = pd.createdAt;
      const date = new Date(utcTimeString);
      respon.push({
        image: img,
        title: title,
        description: desc,
        user: {
          picture: imgp,
          name: name,
          _id: userid,
        },
        book: true,
        createdAt: date,
        _id: _id,
        views: pd.views,
      });
    }
    if (arr.length != darr.length) data.bookmarks = darr;
    await data.save();

    return res.status(200).json({ msg: respon });
  } catch (error) {
    // console.log(error)
    return res.status(400).json({ msg: "error" });
  }
};
exports.showmyposts = async (req, res) => {
  try {
    // [CWE-639] Fix: returns the authenticated caller's own posts only.
    const id = req.user.id;
    const data = await User.findById(id);

    var arr = data.posts;
    var respon = [];
    var img = "";
    var title = "";
    var desc = "";
    var imgp = "";
    var name = "";
    var userid = "";
    var _id = "";
    var view = "";
    var likes = "";
    // console.log(99,arr.length);
    for (var i = 0; i < arr.length; i++) {
      var pd = await Post.findById(arr[i]);
      if (!pd) {
        data.posts.splice(i, 1);
        continue;
      }
      if (pd.views) {
        view = pd.views;
      }
      img = pd.image;
      title = pd.title;
      desc = pd.description;
      userid = pd.user;
      var ud = await User.findById(userid);
      imgp = ud.picture;
      name = ud.name;
      _id = arr[i];
      var likes = pd.likes ? pd.likes : 0;
      const utcTimeString = pd.createdAt;
      const date = new Date(utcTimeString);
      respon.push({
        image: img,
        title: title,
        description: desc,
        user: {
          picture: imgp,
          name: name,
          _id: userid,
        },
        createdAt: date,
        _id: _id,
        views: pd.views,
        createdAt: date,
        powner: true,
        book: false,
        likes: likes,
      });
    }
    data.save();
    return res.status(200).json({ msg: respon });
  } catch (error) {
    return res.status(400).json({ msg: "error" });
  }
};
exports.showyourposts = async (req, res) => {
  try {
    const { id } = req.body;
    const data = await User.findById(id);
    var arr = data.posts;
    var respon = [];
    var img = "";
    var title = "";
    var desc = "";
    var postid = "";
    for (var i = 0; i < arr.length; i++) {
      var pd = await Post.findById(arr[i]);
      img = pd.image;
      title = pd.title;
      desc = pd.description;
      postid = arr[i];
      respon.push({
        img: img,
        title: title,
        desc: desc,
        postid: postid,
      });
      res.status(200).json({ msg: respon });
    }
  } catch (error) {
    // console.log("error in postshow")
    return res.status(400).json({ msg: "error" });
  }
};
exports.follow = async (req, res) => {
  try {
    // [CWE-639] Fix: the actor (id) comes from the verified JWT and only the target (id2) is
    // taken from the body, so nobody can make another user follow someone on their behalf.
    const { id2 } = req.body;
    const id = req.user.id;
    const user = await User.findById(id);
    const user2 = await User.findById(id2);

    var mm = user2.followerscount;
    mm = mm + 1;
    user2.followerscount = mm;
    user2.save();
    var f = 0;
    var m = user.following;
    if (m.length == 0) {
      user.following.push(id2);
    } else {
      for (var i = 0; i < m.length; i++) {
        if (m[i] == id2) {
          f = 1;
          m.splice(i, 1);
          m.push(id2);
        }
      }
      if (!f) {
        m.push(id2);
      }

      user.following = m;
    }
    user.followingcount = user.followingcount + 1;
    user.save();
    return res.status(200).json({ msg: "ok" });
  } catch (error) {
    // console.log("error in follow");
    return res.status(400).json({ msg: "error in follow" });
  }
};
exports.followercount = async (req, res) => {
  try {
    const { id } = req.body;
    const user = await User.findById(id);
    var count = user.followerscount;
    return res.status(200).json({ msg: count });
  } catch (error) {
    // console.log("error in followcount");
    return res.status(400).json({ msg: "error in followcount" });
  }
};
exports.followingcount = async (req, res) => {
  try {
    const { id } = req.body;
    const user = await User.findById(id);
    var count = user.followingcount;
    return res.status(200).json({ msg: count });
  } catch (error) {
    // console.log("error in followingcount");
    return res.status(400).json({ msg: "error in followingcount" });
  }
};
exports.unfollow = async (req, res) => {
  try {
    // [CWE-639] Fix: actor (id) from the verified JWT; only the target (id2) from the body.
    const { id2 } = req.body;
    const id = req.user.id;
    const user = await User.findById(id);
    const user2 = await User.findById(id2);
    var mm = user2.followerscount;
    if (mm - 1 < 0) {
      mm = 0;
    } else {
      mm = mm - 1;
    }
    user2.followerscount = mm;
    user2.save();
    var f = 0;
    var m = user.following;
    if (m.length == 0) {
      return res.status(200).json({ msg: "ok" });
      // user.following.push(id2);
    } else {
      for (var i = 0; i < m.length; i++) {
        if (m[i] == id2) {
          f = 1;
          m.splice(i, 1);
        }
      }
      user.following = m;
    }
    var f = user.followingcount;
    f = f - 1;
    if (f < 0) {
      f = 0;
    }
    user.followingcount = f;
    user.save();
    res.status(200).json({ msg: "ok" });
  } catch (error) {
    // console.log("error in unfollow");
    res.status(400).json({ msg: "error in unfollow" });
  }
};
exports.fetchfollowing = async (req, res) => {
  try {
    // [CWE-639] Fix: previously returned any user's following list for a body-supplied id.
    const id = req.user.id;
    const user = await User.findById(id);
    const arr = user.following;
    const resp = [];
    var name = "";
    var pic = "";
    var pid = "";
    for (var i = 0; i < arr.length; i++) {
      var dat = await User.findById(arr[i]);
      name = dat.name;
      pic = dat.picture;
      pid = arr[i];
      resp.push({
        name: name,
        pic: pic,
        pid: pid,
      });
    }
    return res.status(200).json({ msg: resp });
  } catch (error) {
    // console.log("error in fetchfollow");
    return res.status(400).json({ msg: "error in fetchfollow" });
  }
};
exports.changeabout = async (req, res) => {
  try {
    // [CWE-639] Fix: only the authenticated user can edit their own "about"; the previous
    // version wrote to whichever id the caller put in the body.
    const { about } = req.body;
    const id = req.user.id;
    const user = await User.findById(id);
    user.about = about;
    user.save();
    return res.status(200).json({ msg: "Saved successfully" });
  } catch (error) {
    // console.log("error in fetchfollow");
    return res.status(400).json({ msg: "error in fetchfollow" });
  }
};
exports.searchresult = async (req, res) => {
  try {
    const { id2 } = req.body;
    const data = await User.find({
      name: { $regex: "^" + `${id2}`, $options: "i" },
    });
    if (data.length === 0) {
      return res.status(200).json({ msg: [] });
    }
    var names = [];
    for (var i = 0; i < data.length; i++) {
      var name = data[i].name;
      var id = data[i]._id;
      var pic = data[i].picture;
      names.push({
        name: name,
        id: id,
        pic: pic,
      });
    }
    return res.status(200).json({ msg: names });
  } catch (error) {
    // console.log("error in search");
    return res.status(400).json({ msg: "error in search" });
  }
};

exports.checkfollowing = async (req, res) => {
  try {
    // [CWE-639] Fix: actor (id) from the verified JWT; only the target (id2) from the body.
    const { id2 } = req.body;
    const id = req.user.id;
    const user = await User.findById(id);
    const arr = user.following;
    if (arr.length == 0) {
      return res.status(200).json({ msg: "not" });
    }
    for (var i = 0; i < arr.length; i++) {
      if (arr[i] === id2) {
        return res.status(200).json({ msg: "ok" });
      }
    }
    return res.status(200).json({ msg: "not" });
  } catch (error) {
    // console.log("error in fetchcehckfollow");
    return res.status(400).json({ msg: "error in fetchcheckfollow" });
  }
};

exports.deletepost = async (req, res) => {
  try {
    // [CWE-639] Fix: owner is derived from the verified JWT, not the request body.
    const { postid } = req.body;
    const userid = req.user.id;

    // [CWE-639] Fix: ownership must be enforced on the POST itself, not only on the caller's
    // posts array. The previous version ran Post.deleteOne({ _id: postid }) with no owner
    // check at all, so any authenticated user could destroy anybody's post just by knowing
    // its id. Compare the post's owner against the token subject and reject otherwise.
    const post = await Post.findById(postid);
    if (!post) {
      return res.status(404).json({ mgs: "Post not found" });
    }
    if (post.user.toString() !== userid) {
      return res.status(403).json({ mgs: "Not allowed" });
    }

    await Post.deleteOne({ _id: postid });
    var datas = await User.findById(userid);
    arr = datas.posts;
    for (var i = 0; i < arr.length; i++) {
      if (arr[i] == postid) {
        arr.splice(i, 1);
        break;
      }
    }
    datas.posts = arr;
    // [CWE-639] Fix: await the write; the unawaited save could fail after the 200 was sent.
    await datas.save();
    return res.status(200).json({ mgs: "ok" });
  } catch (error) {
    // console.log("error in deleting post");
    return res.status(400).json({ mgs: "Error" });
  }
};
exports.login = async (req, res) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ message: "Invalid input." });
    }
    const { temail, password } = parsed.data;
    const user = await User.findOne({ email: temail });

    // [CWE-204] Every failed-authentication branch below returns this one response.
    // Previously the three branches were distinguishable -- "the email you entered is
    // not registered" vs "You have account associated with google" vs "Invalid
    // Credentials" -- which let an unauthenticated caller test any address and learn
    // both whether an account exists and which auth method it uses.
    const invalidCredentials = () =>
      res.status(400).json({ message: "Invalid email or password." });

    // [CWE-208] Equalise timing. bcrypt.compare only ran when the user existed, so an
    // unknown email returned in ~2ms and a known one in ~200ms at cost 12 -- a clock
    // is just as good an oracle as an error message. Comparing against a throwaway
    // hash of the same cost makes both paths do the same work.
    if (!user || user.googleId) {
      await bcrypt.compare(password, DUMMY_HASH);
      return invalidCredentials();
    }

    const check = await bcrypt.compare(password, user.password);
    if (!check) {
      return invalidCredentials();
    }
    if (user.verify === false) {
      return res.status(403).json({
        message: "Email not verified. Please verify your email to log in.",
        needVerify: true,
        email: user.email,
      });
    }

    // [CWE-613] Fix: short-lived (15m default) access token plus a rotating refresh
    // cookie, instead of a hardcoded 15-day JWT that could not be revoked.
    // [CWE-384] Note: no session regeneration is performed on this path, deliberately.
    // This login is stateless — identity travels in the signed JWT and never in req.session
    // — and with `saveUninitialized: false` no session identifier is issued before
    // authentication, so there is no pre-auth session id for an attacker to fixate.
    // Regeneration is applied where the session genuinely carries identity instead:
    // controllers/Auth.js's google_auth_callback.
    const token = generateToken({ id: user._id.toString() });
    const { rawToken } = await issueRefreshToken(user._id);
    setRefreshCookie(res, rawToken);
    res.send({
      id: user._id,
      name: user.name,
      picture: user.picture,
      token: token,
      bookmark: user.bookmarks,
      likes: user.likes,
    });
  } catch (error) {
    // console.log(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
exports.uploadprofile = async (req, res) => {
  try {
    const { picture, about } = req.body;

    await User.findByIdAndUpdate(req.user.id, {
      picture: picture,
      about: about,
    });
    res.status(200).json({ picture, about });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
exports.getUser = async (req, res) => {
  try {
    const { userId } = req.params;
    // [CWE-200/CWE-359] The previous line destructured a Mongoose *document*:
    // `password` came from a prototype getter, but the rest element copied only
    // the own enumerable keys ($__ and _doc) — so the bcrypt hash and the email
    // still went out inside _doc. Project the fields in the query and return an
    // explicit allowlist DTO instead.
    const user = await User.findById(userId).select(
      "name picture about followerscount followingcount createdAt"
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json(toPublicUser(user));
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
// [CWE-204] findOutUser was removed. Its only purpose was to tell an unauthenticated
// caller whether an email address had an account (200 with the user object vs 404 vs a
// distinct 400 for Google accounts), which is the enumeration oracle itself -- there is
// no way to answer that question safely while still answering it. The reset flow no
// longer needs it: since the [CWE-640] fix, sendResetPasswordCode returns the same
// response for every address, so the client posts the typed email straight to it.
// See client/src/pages/ResetPassword.js.
exports.sendResetPasswordCode = async (req, res) => {
  // [CWE-640] Fix: the response is now identical whether or not the address is registered,
  // so this endpoint can no longer be used to enumerate accounts. Previously an unknown
  // email dereferenced null (user._id) and returned 500 while a known email returned 200 —
  // a trivially observable oracle.
  const uniformResponse = {
    message: "If that email address is registered, a reset code has been sent.",
  };
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      // Mongoose 8 removed findOneAndRemove(); the original code called it here, so this
      // endpoint threw a TypeError and 500'd for EVERY email — password reset never worked.
      await Code.findOneAndDelete({ user: user._id });
      const code = generateCode(6);
      await new Code({
        code,
        user: user._id,
      }).save();
      sendResetCode(user.email, user.name, code);
    }
    return res.status(200).json(uniformResponse);
  } catch (error) {
    // Deliberately generic: the failure mode must not correlate with whether the lookup hit.
    res.status(500).json({ message: "Something went wrong" });
  }
};
exports.validateResetCode = async (req, res) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ email });

    // [CWE-640] Fix: one generic failure covers both "no such user" and "wrong code", so
    // this endpoint cannot be used to probe which addresses are registered. It also avoids
    // the TypeError (and 500) the previous version threw when `user` was null.
    const invalid = { message: "Invalid or expired reset code" };
    if (!user) {
      return res.status(400).json(invalid);
    }

    const Dbcode = await Code.findOne({ user: user._id });
    if (!Dbcode) {
      return res.status(400).json(invalid);
    }

    // [CWE-640] Fix: explicit 30-minute expiry. The TTL index alone is not enough — Mongo's
    // TTL monitor only sweeps about once a minute, and before `timestamps` was added to the
    // Code schema createdAt was never stored, so codes never expired at all.
    const THIRTY_MIN = 30 * 60 * 1000;
    if (Date.now() - new Date(Dbcode.createdAt).getTime() > THIRTY_MIN) {
      await Code.findByIdAndDelete(Dbcode._id);
      return res.status(400).json(invalid);
    }

    // [CWE-640] Fix: burn the code after 5 wrong attempts so it cannot be brute-forced.
    if (Dbcode.attempts >= 5) {
      await Code.findByIdAndDelete(Dbcode._id);
      return res.status(400).json(invalid);
    }

    if (String(Dbcode.code) !== String(code)) {
      Dbcode.attempts += 1;
      await Dbcode.save();
      return res.status(400).json(invalid);
    }

    // [CWE-640] Fix: hand back a short-lived ticket instead of a bare `ok`. Previously the
    // client received no credential at all, which is why changePassword had to accept
    // whatever email the caller supplied. The target user is now bound into the ticket.
    const resetTicket = await issueResetTicket(user._id);

    // Make the emailed code single-use too, so it cannot mint a second ticket.
    await Code.findOneAndDelete({ user: user._id });

    return res.status(200).json({ message: "ok", resetTicket });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
};
exports.changePassword = async (req, res) => {
  // [CWE-620] Fix: this endpoint no longer accepts an `email` at all. The previous contract
  // was `{ email, password }` with no authentication, no code check and no ticket, so any
  // anonymous caller could overwrite any account's password simply by naming it. The target
  // user now comes from the verified `userId` claim inside the reset ticket, and nothing in
  // the request body can influence whose password is changed.
  const { resetTicket, newPassword } = req.body;
  const rejected = { message: "Invalid or expired reset ticket" };
  try {
    const verified = await verifyResetTicket(resetTicket);
    if (!verified.ok) {
      return res.status(401).json(rejected);
    }

    const user = await User.findById(verified.userId).select("email name");
    if (!user) {
      return res.status(401).json(rejected);
    }

    // V15 password policy preserved. This runs BEFORE the ticket is consumed, so a password
    // that fails the policy can be retried with the same ticket instead of restarting the
    // whole flow. Name and email are passed in so zxcvbn penalises passwords derived from
    // the user's own identity, as V15 intended.
    const pwCheck = validatePassword(newPassword, [user.email, user.name]);
    if (!pwCheck.ok) {
      return res.status(400).json({ message: pwCheck.message });
    }

    // [CWE-640] Fix: single-use enforcement, consumed atomically before the write so a
    // replayed ticket can never reach the password update.
    const consumed = await consumeResetTicket(resetTicket);
    if (!consumed.ok) {
      return res.status(401).json(rejected);
    }

    const cryptedPassword = await bcrypt.hash(newPassword, BCRYPT_COST);
    await User.findByIdAndUpdate(consumed.userId, {
      password: cryptedPassword,
    });

    // [CWE-613] Fix: end every existing session for this account. This was the item the V12
    // task deferred to V1, and it matters most here — a password reset is exactly when a
    // stolen refresh token must stop working.
    await revokeAllForUser(consumed.userId);

    return res.status(200).json({ message: "ok" });
  } catch (error) {
    res
      .status(400)
      .json({ message: "AN ERROR OCCURRED, PLEASE TRY AGAIN LATER" });
  }
};
