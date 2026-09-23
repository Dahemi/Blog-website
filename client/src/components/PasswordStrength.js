import zxcvbn from "zxcvbn";

const LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
const COLORS = ["#c0392b", "#e67e22", "#f1c40f", "#27ae60", "#16a085"];

// V15: this is UX feedback only, not enforcement. The real check is server-side
// validatePassword() in backend/helper/passwordPolicy.js — anyone can bypass this
// component entirely (a different client, curl, editing the JS in DevTools).
export default function PasswordStrength({ password, userInputs = [] }) {
  if (!password) return null;
  const { score, feedback } = zxcvbn(password, userInputs);
  return (
    <div style={{ marginTop: 6, marginBottom: 6 }}>
      <div style={{ height: 6, background: "#eee", borderRadius: 3 }}>
        <div
          style={{
            width: `${((score + 1) / 5) * 100}%`,
            height: "100%",
            background: COLORS[score],
            borderRadius: 3,
            transition: "width .2s",
          }}
        />
      </div>
      <small style={{ color: COLORS[score] }}>
        {LABELS[score]}
        {score < 3 && feedback.warning ? ` — ${feedback.warning}` : ""}
      </small>
      {score < 3 && (
        <small style={{ display: "block", color: "#777" }}>
          Needs to reach "Strong" before you can continue.
        </small>
      )}
    </div>
  );
}
