import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Cookies from "js-cookie";
import { useDispatch } from "react-redux";

export default function OAuthCallback() {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [error, setError] = useState("");

  useEffect(() => {
    // The token arrives in the fragment. Read it, then clear the hash immediately
    // so it does not persist in browser history or the address bar.
    const params = new URLSearchParams(window.location.hash.slice(1));
    window.history.replaceState(null, "", window.location.pathname);

    const err = params.get("error");
    if (err) return setError(errorMessage(err));

    const token = params.get("token");
    const id = params.get("id");
    if (!token || !id) return setError("Sign-in did not complete. Please try again.");

    // Field names match the local-login response shape (controllers/user.js's
    // `login`) exactly — every component that reads the logged-in user (PostCard,
    // Article, UserProfile, ...) uses user.id, never user._id.
    const user = {
      id,
      token,
      name: params.get("name") || "",
      picture: params.get("picture") || "",
      likes: safeParseArray(params.get("likes")),
      bookmarks: safeParseArray(params.get("bookmarks")),
    };

    // Matches how the local login path stores state today (see reducers/userReducer.js).
    Cookies.set("user", JSON.stringify(user), { expires: 1, sameSite: "lax" });
    dispatch({ type: "LOGIN", payload: user });
    navigate("/", { replace: true });
  }, [dispatch, navigate]);

  if (error) {
    return (
      <div style={{ padding: 40, textAlign: "center" }}>
        <h2>Could not sign you in</h2>
        <p>{error}</p>
        <button onClick={() => navigate("/auth")}>Back to sign in</button>
      </div>
    );
  }
  return <div style={{ padding: 40, textAlign: "center" }}>Signing you in…</div>;
}

function safeParseArray(raw) {
  try {
    const parsed = JSON.parse(raw || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    return [];
  }
}

// Deliberately vague about whether an account exists — same reasoning as the
// uniform-error fix for user enumeration (V5).
function errorMessage(code) {
  switch (code) {
    case "email_not_verified":
      return "Your Google account's email address is not verified. Verify it with Google and try again.";
    case "access_denied":
      return "You cancelled the Google sign-in.";
    case "state_mismatch":
    case "nonce_mismatch":
    case "no_pending_authorization":
    case "authorization_expired":
      return "The sign-in request expired or could not be verified. Please try again.";
    default:
      return "Sign-in failed. Please try again.";
  }
}
