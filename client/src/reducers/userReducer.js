
import Cookies from "js-cookie";

// A malformed/empty "user" cookie must not throw here: this runs while the
// store is being created, so a parse error takes down the whole app.
const storedUser = () => {
  const raw = Cookies.get("user");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (error) {
    Cookies.remove("user");
    return null;
  }
};

export function userReducer(state = storedUser(), action) {
  switch (action.type) {
    case "LOGIN":
      return action.payload;
    case "LOGOUT":
      return null;
    case "UPDATEPICTURE":
      return { ...state, picture: action.payload.picture, about: action.payload.about };
    case "VERIFY":
      return { ...state, verified: action.payload };
    case "LIKE":
      return { likes: action.payload, ...state };
    case "BOOKMARK":
      return { ...state, bookmarks: action.payload };
    default:
      return state;
  }
}
 
