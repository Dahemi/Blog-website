// [CWE-200 / CWE-359] Public projection of a User document.
//
// Allowlist, not denylist: only the fields named here can ever reach a client.
// A denylist (deleting `password` from a spread) fails open the moment a new
// sensitive field is added to the schema — which is exactly how V6 happened.
const toPublicUser = (user) => {
  if (!user) return null;
  return {
    _id: user._id,
    name: user.name,
    picture: user.picture,
    about: user.about,
    followerscount: user.followerscount,
    followingcount: user.followingcount,
    createdAt: user.createdAt,
  };
};

module.exports = { toPublicUser };
