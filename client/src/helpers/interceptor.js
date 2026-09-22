import axios from "axios";
import Cookies from "js-cookie";

// [CWE-613] Fix: the access token now expires after 15 minutes (previously 15 days), so
// the client must transparently exchange its httpOnly refresh cookie for a new access
// token instead of silently failing or bouncing the user to the login page.

const REFRESH_URL = `${process.env.REACT_APP_BACKEND_URL}/auth/refresh`;
const USER_COOKIE = "user";
const USER_COOKIE_DAYS = 15;

// Single-flight guard. If several requests 401 at once we must only send ONE refresh:
// the refresh token is single-use, so a second concurrent exchange would look like
// token reuse and revoke every session for the user.
let refreshPromise = null;

const requestRefresh = () => {
  if (!refreshPromise) {
    refreshPromise = axios
      .post(REFRESH_URL, {}, { withCredentials: true })
      .then((response) => response.data)
      .finally(() => {
        // Released on the next tick so requests that 401 in the same batch join this
        // refresh rather than starting a competing one.
        setTimeout(() => {
          refreshPromise = null;
        }, 0);
      });
  }
  return refreshPromise;
};

// [CWE-613] Fix: keep Redux and the persisted cookie in sync with the refreshed token,
// preserving the rest of the stored user object.
const persistRefreshedToken = (store, data) => {
  const current = store.getState().user || {};
  const nextUser = { ...current, token: data.token, id: data.id || current.id };
  store.dispatch({ type: "LOGIN", payload: nextUser });
  Cookies.set(USER_COOKIE, JSON.stringify(nextUser), {
    expires: USER_COOKIE_DAYS,
  });
  return nextUser;
};

const endSession = (store) => {
  Cookies.remove(USER_COOKIE);
  store.dispatch({ type: "LOGOUT" });
  if (window.location.pathname !== "/auth") {
    window.location.assign("/auth");
  }
};

export const setupAxiosInterceptors = (store) => {
  axios.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config;
      const status = error.response ? error.response.status : null;
      const isRefreshCall =
        originalRequest &&
        originalRequest.url &&
        originalRequest.url.includes("/auth/refresh");

      // Only a 401 is worth retrying, and never more than once per request.
      if (
        status !== 401 ||
        !originalRequest ||
        originalRequest._retry ||
        isRefreshCall
      ) {
        return Promise.reject(error);
      }

      originalRequest._retry = true;

      try {
        const data = await requestRefresh();
        const nextUser = persistRefreshedToken(store, data);

        // Retry with the NEW token: the original config still carries the stale one.
        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers.Authorization = `Bearer ${nextUser.token}`;

        return axios(originalRequest);
      } catch (refreshError) {
        // Refresh cookie is gone, expired, or was revoked: the session is truly over.
        endSession(store);
        return Promise.reject(refreshError);
      }
    },
  );
};
