// Seeds one sample author + one sample blog post.
// Usage (from the backend folder):  node seed/sampleblog.js
//
// Safe to re-run: it reuses the author and skips the post if the title exists.

require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const keys = require("../config/keys");
const User = require("../models/User");
const Post = require("../models/Post");

const AUTHOR = {
  name: "Olawale Adeyawa",
  email: "serendipity.author@example.com",
  password: "sample123",
};

// NOTE: `category` must be one of: food | travelling | lifestyle | tech
const POST = {
  title: "Serendipity",
  description:
    "The quiet magic of finding something beautiful when you weren't even looking.",
  category: "lifestyle",
  image:
    "https://res.cloudinary.com/zkyysfzm/image/upload/v1/blogs/serendipity_hero.jpg",
  views: 128,
  likes: 24,
  content: `
    <h2>The quiet magic of the unplanned</h2>
    <p>
      There is a particular kind of joy that cannot be scheduled. It arrives sideways,
      unannounced, on a road you only took because the other one was closed. We have a
      word for it, and the word is <em>serendipity</em>.
    </p>

    <h3>Where the word comes from</h3>
    <p>
      Horace Walpole coined it in 1754, in a letter describing a Persian fairy tale
      about the three princes of Serendip &mdash; travellers who were "always making
      discoveries, by accidents and sagacity, of things they were not in quest of."
      That last clause is the whole idea. Not luck alone. Luck <strong>plus</strong>
      the presence of mind to notice it.
    </p>

    <blockquote>
      Chance favours only the prepared mind. &mdash; Louis Pasteur
    </blockquote>

    <h3>Three small rules for finding it</h3>
    <ol>
      <li><strong>Leave margin.</strong> A day packed end to end has no room for detours.</li>
      <li><strong>Look up.</strong> Most of what we miss is above eye level or behind us.</li>
      <li><strong>Follow the tangent.</strong> The interesting thing is rarely the thing you came for.</li>
    </ol>

    <h3>An open field, a bank of cloud</h3>
    <p>
      I did not plan to stop here. The hills went green to the horizon and the clouds
      stacked up like something being built. I had been driving for hours toward
      somewhere else entirely, and somewhere else could wait.
    </p>
    <p>
      That is the whole of it, really. You cannot go looking for serendipity &mdash; the
      looking is what prevents it. You can only make yourself the kind of person who
      is still paying attention when it shows up.
    </p>
  `.trim(),
};

(async () => {
  await mongoose.connect(keys.MONGO_URI);

  let author = await User.findOne({ email: AUTHOR.email });
  if (!author) {
    author = await new User({
      name: AUTHOR.name,
      email: AUTHOR.email,
      password: await bcrypt.hash(AUTHOR.password, 10),
      verify: true,
      about: "Writes about slow travel, type, and paying attention.",
      likeslist: {},
      bookmarkslist: {},
    }).save();
    console.log(`created author ${author.email} (password: ${AUTHOR.password})`);
  } else {
    console.log(`reusing author ${author.email}`);
  }

  const existing = await Post.findOne({ title: POST.title, user: author._id });
  if (existing) {
    console.log(`post "${POST.title}" already exists: ${existing._id}`);
  } else {
    const post = await new Post({ ...POST, user: author._id }).save();
    author.posts.push(post._id);
    await author.save();
    console.log(`created post "${post.title}": ${post._id}`);
  }

  await mongoose.disconnect();
})().catch(async (err) => {
  console.error("seed failed:", err.message);
  await mongoose.disconnect();
  process.exit(1);
});
