import axios from "axios";
import { useState } from "react";
import "./resetPassword.css";
import { Link, useNavigate, Navigate } from "react-router-dom";
import PasswordStrength from "../components/PasswordStrength";

function ResetPassword() {
  const [email, setEmail] = useState("");
  const [code, setcode] = useState("");
  const [pass, setpass] = useState("");
  const [foundUser, setFoundUser] = useState(null);
  const [foundsend, setFoundsend] = useState(null);
  const [open, setopen] = useState(null);
  // [CWE-640] Fix: holds the short-lived reset ticket returned by /validateResetCode. It is
  // the only thing that authorises the password change — the old flow sent a raw email.
  const [resetTicket, setResetTicket] = useState("");

  const navigate = useNavigate();

  const handleInputChange = (event) => {
    setEmail(event.target.value);
  };

  const handleSearchClick = async () => {
    try {
      const { data } = await axios.post(
        `${process.env.REACT_APP_BACKEND_URL}/findOutUser`,
        {
          email,
        },
      );

      setFoundUser(data[0]);
    } catch (error) {
      if (error.response.status === 400) {
        alert(error.response.data.message);
        return;
      }
      if (error.response.status === 404) {
        alert(error.response.data.message);
        return;
      }
    }
  };
  const sendCode = async () => {
    try {
      const { data } = await axios.post(
        `${process.env.REACT_APP_BACKEND_URL}/sendResetPasswordCode`,
        { email: foundUser.email, code: code },
      );
      setFoundsend(true);
    } catch (error) {
      // console.log(error.message);
    }
  };

  const validate = async (e) => {
    e.preventDefault();
    try {
      const { data } = await axios.post(
        `${process.env.REACT_APP_BACKEND_URL}/validateResetCode`,
        { email: foundUser.email, code: code },
      );
      if (data.message === "ok") {
        // [CWE-640] Fix: the server returns a signed, single-use ticket alongside `ok`.
        // Keep it — changep() must present it to authorise the password change.
        setResetTicket(data.resetTicket);
        setFoundsend(false);
        setopen(true);
      } else {
        alert(data.message);
      }
    } catch (error) {
      // console.log(error.message)
    }
  };
  const changep = async (e) => {
    e.preventDefault();
    // V15: this used to check pass.length <= 8 client-side — a stale rule left
    // over from before the server enforced anything at all. The real policy
    // (12-char minimum, zxcvbn score, 72-byte max) is enforced server-side in
    // validatePassword(); its message comes back through the existing
    // `else { alert(data.message) }` branch below, so no client-side length
    // check is needed here.
    // The ticket comes from validate(); without it the server rejects the change with 401.
    if (!pass || !resetTicket) {
      return;
    }

    try {
      // [CWE-620] Fix: changePassword no longer accepts an email. The target user is taken
      // from the ticket's signed userId claim, so the client cannot choose whose password
      // gets changed.
      const { data } = await axios.post(
        `${process.env.REACT_APP_BACKEND_URL}/changePassword`,
        { resetTicket, newPassword: pass },
      );
      if (data.message === "ok") {
        alert("Password Changed");
        setTimeout(() => {
          navigate("/");
        }, 2000);
      } else {
        alert(data.message);
      }
    } catch (error) {
      alert(error.message);
    }
  };
  return (
    <div className="user-search">
      {" "}
      {/* Add the "user-search" class to the container */}
      <label htmlFor="email-input">Email address:</label>
      <input
        type="email"
        id="email-input"
        value={email}
        onChange={handleInputChange}
        className="user-search-input"
      />
      <button onClick={handleSearchClick} className="user-search-button">
        Search
      </button>
      {foundUser ? (
        <div className="user-search-results">
          <p>Name: {foundUser.name}</p>
          <p>Email: {foundUser.email}</p>
          <p>
            picture: <img className="imgres" src={foundUser.picture} alt="" />
          </p>
          <button onClick={sendCode}>send code</button>
        </div>
      ) : (
        <p className="user-search-no-results">
          No user found with that email address.
        </p>
      )}
      <div className={`${foundsend ? "" : "hidden"}`}>
        <form className="">
          <label htmlFor="email-input">Code Has been Sent to your email</label>
          <input
            type="text"
            // id="email-input"
            value={code}
            placeholder="CODE"
            onChange={(e) => {
              setcode(e.target.value);
            }}
            className="user-search-input"
          />
          <button onClick={validate}>Verify</button>
        </form>
      </div>
      <div className={`${open ? "" : "hidden"}`}>
        <form className="">
          <label htmlFor="email-input">Enter Your new Password</label>
          <input
            type="password"
            // id="email-input"
            value={pass}
            placeholder="NEW PASSWORD"
            onChange={(e) => {
              setpass(e.target.value);
            }}
            className="user-search-input"
          />
          <PasswordStrength password={pass} userInputs={[foundUser?.email]} />
          <button onClick={(e) => changep(e)}>Confirm</button>
        </form>
      </div>
    </div>
  );
}

export default ResetPassword;
