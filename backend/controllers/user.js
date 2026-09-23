const { validateEmail, validateLength } = require("../helper/validation");
const User = require("../models/User");
const Post = require("../models/Post");
const bcrypt = require("bcrypt");
const { generateToken } = require("../helper/token");
// [CWE-613] Fix: rotating refresh tokens replace the previous 15-day access JWT.
const {
  issueRefreshToken,
  setRefreshCookie,
} = require("../helper/refreshToken");
const Code = require("../models/Code");
const { sendResetCode } = require("../helper/mail");
const { sendReportMail } = require("../helper/reportmail");
const generateCode = require("../helper/gen_code");
const { validatePassword, BCRYPT_COST } = require("../helper/passwordPolicy");

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
      verify: true,
      likeslist: {},
      bookmarkslist: {},
    }).save();
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
    const { temail, password } = req.body;
    const user = await User.findOne({ email: temail });
    if (!user) {
      return res.status(400).json({
        message: "the email you entered is not registered.",
      });
    }
    if (user.googleId) {
      return res.status(400).json({
        message:
          "You have account associated with google, trying signing up again using google",
      });
    }
    const check = await bcrypt.compare(password, user.password);
    if (!check) {
      return res.status(400).json({
        message: "Invalid Credentials. Please Try Again.",
      });
    }
    // [CWE-613] Fix: short-lived (15m default) access token plus a rotating refresh
    // cookie, instead of a hardcoded 15-day JWT that could not be revoked.
    // [CWE-384] Note: no session regeneration is performed on this path, deliberately.
    // This login is stateless — identity travels in the signed JWT and never in req.session
    // — and with `saveUninitialized: false` no session identifier is issued before
    // authentication, so there is no pre-auth session id for an attacker to fixate.
    // Regeneration is applied where the session genuinely carries identity instead: the
    // Google OAuth callback and POST /login/success in routes/user.js.
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
    const user = await User.findById(userId);
    const { password, ...otherdata } = user;
    res.status(200).json(otherdata);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
exports.findOutUser = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email });
    if (user) {
      if (!user.googleId) {
        res.status(200).json(user);
      } else {
        return res.status(400).json({
          message:
            "You have account associated with google, trying signing up again using google",
        });
      }
    } else {
      res.status(404).json({ message: "no such user exists" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
exports.sendResetPasswordCode = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    await Code.findOneAndRemove({ user: user._id });
    const code = generateCode(5);
    const savedCode = await new Code({
      code,
      user: user._id,
    }).save();
    sendResetCode(user.email, user.name, code);
    return res.status(200).json({
      message: "Email reset code has been sent to your email",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
exports.validateResetCode = async (req, res) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ email });
    const Dbcode = await Code.findOne({ user: user._id });
    if (Dbcode.code !== code) {
      return res.status(400).json({
        message: "Verification code is wrong!",
      });
    }
    return res.status(200).json({ message: "ok" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
exports.changePassword = async (req, res) => {
  const { email, password } = req.body;
  try {
    // V15: this endpoint previously performed no validation at all — a
    // single-character password was accepted. (The missing authentication here
    // is V1, tracked and fixed separately.)
    const pwCheck = validatePassword(password, [email]);
    if (!pwCheck.ok) {
      return res.status(400).json({ message: pwCheck.message });
    }
    const cryptedPassword = await bcrypt.hash(password, BCRYPT_COST);
    await User.findOneAndUpdate(
      { email },
      {
        password: cryptedPassword,
      },
    );
    return res.status(200).json({ message: "ok" });
  } catch (error) {
    res
      .status(400)
      .json({ message: "AN ERROR OCCURRED, PLEASE TRY AGAIN LATER" });
  }
};
