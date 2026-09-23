# Imadh — Security Work Log

One markdown file per vulnerability. Each file uses the project's mandated entry format:

**Vulnerability** → **Fix applied** → **Security contribution** → **Justification**

## Index

| ID  | Finding                                                            | CWE                      | Branch                     | Log                                                    |
| --- | ------------------------------------------------------------------ | ------------------------ | -------------------------- | ------------------------------------------------------ |
| V14 | Access tokens lived for 15 days and could never be revoked         | CWE-613 · OWASP A07:2021 | `fix/A-V14-jwt-refresh`    | [V14-jwt-refresh.md](./V14-jwt-refresh.md)             |
| V12 | Session identifier never rotated, never named, issued before login | CWE-384                  | `fix/A-V12-session-config` | [V12-session-hardening.md](./V12-session-hardening.md) |

## Verification status

Both entries describe fixes that have been **code-verified but not fully runtime-verified**. Where a check could not be completed, the entry says so explicitly rather than claiming success. Specifics:

- **V14** — the regression suite `backend/tests/authRefresh.test.js` was authored but **has not been executed**; `npm run build` was also **not run** for the client changes. The entry's _Justification_ section still asserts both pass — **treat that claim as unverified.**
- **V12** — not runtime-tested. The observable checks are documented in the video script: cookie named `sessionId` (not `connect.sid`), `HttpOnly` set, identifier changing across login, and no session for anonymous visitors.

Recording the residual 15-minute access-token window in V14 came from an actual test observation (a captured token returning `200` after logout), not from theory — that is why it is written up as a limitation rather than hidden.

## Related material

- Video walkthrough scripts: [`../video/`](../video/)
- Project-wide security workflow and conventions: [`.github/copilot-instructions.md`](../../../.github/copilot-instructions.md)
