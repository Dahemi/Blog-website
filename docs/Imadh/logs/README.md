# Imadh — Security Work Log

One markdown file per vulnerability. Each file uses the project's mandated entry format:

**Vulnerability** → **Fix applied** → **Security contribution** → **Justification**

## Index

| ID  | Finding                                                            | CWE                      | Branch                       | Log                                                    |
| --- | ------------------------------------------------------------------ | ------------------------ | ---------------------------- | ------------------------------------------------------ |
| V14 | Access tokens lived for 15 days and could never be revoked         | CWE-613 · OWASP A07:2021 | `fix/A-V14-jwt-refresh`      | [V14-jwt-refresh.md](./V14-jwt-refresh.md)             |
| V12 | Session identifier never rotated, never named, issued before login | CWE-384                  | `fix/A-V12-session-config`   | [V12-session-hardening.md](./V12-session-hardening.md) |
| V3  | User-owned routes trusted a user id from the request body (IDOR)   | CWE-639 · OWASP A01:2021 | `fix/Imaadh-V3-owner-checks` | [V3-owner-checks.md](./V3-owner-checks.md)             |

## Verification status

Three entries. All fixes are code-verified; runtime verification varies by entry, and where a check could not be completed the entry says so explicitly rather than claiming success.

- **V14** — `backend/tests/authRefresh.test.js` **now executes and passes**, verified 2026-09-23 while adding V3 (38 tests across 2 suites via `npm test`). Running it required installing `helmet`, which the merged V10 security-headers work had declared in `backend/package.json` but never installed — until then `app.js` could not even be required, so no test could run. **The client `npm run build` has still not been run**, so that part of the entry's Justification remains unverified.
- **V12** — not runtime-tested. The observable checks are documented in the video script: cookie named `sessionId` (not `connect.sid`), `HttpOnly` set, identifier changing across login, and no session for anonymous visitors.
- **V3** — backend suite `backend/tests/idor.test.js` passes (32 cases; see the entry). The **client-side request interceptor has not been exercised in a browser**, so the end-to-end flow is unverified: log in, load the feed and an article, and confirm protected calls such as `/checkbookmark` now carry an `Authorization` header and return 200 rather than 401.

Recording the residual 15-minute access-token window in V14 came from an actual test observation (a captured token returning `200` after logout), not from theory — that is why it is written up as a limitation rather than hidden.

## Related material

- Video walkthrough scripts: [`../video/`](../video/)
- Project-wide security workflow and conventions: [`.github/copilot-instructions.md`](../../../.github/copilot-instructions.md)
