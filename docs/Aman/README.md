# Aman — Security Evidence

Infrastructure Hardening & OpenID Connect Lead
Owned vulnerabilities: V8, V10, V13, V15 + Google OpenID Connect implementation

All "before" evidence captured 21–22 September 2026, prior to any remediation commit.
Organised into a `V<n>/` subfolder per vulnerability inside `scans/`, `pocs/` and
`screenshots/`, so each team member's evidence sits alongside theirs without collisions —
see the team-wide layout note at the bottom.

## Evidence index

| File | What it proves | Finding | Report ref |
|---|---|---|---|
| `scans/V8/npm-audit-before.txt` | 26 backend advisories: 5 low, 5 moderate, 14 high, 2 critical | V8 | Fig 7, 3.8 |
| `scans/V8/npm-audit-before.json` | Structured advisory data for reachability analysis | V8 | 3.8 |
| `scans/V8/npm-audit-client-before.txt` | Separate frontend dependency tree — 81 advisories, 4 critical | V8 | 4.2 |
| `scans/V8/npm-audit-client-before.json` | Same, structured | V8 | 4.2 |
| `scans/V8/retire-before.json` | Independent corroboration from a second advisory database | V8 | 2.2 |
| `screenshots/V8/fig-07-npm-audit-before.jpg` | Backend summary line, "26 vulnerabilities" | V8 | Fig 7, 3.8 |
| `screenshots/V8/fig-07-npm-audit-client-before.png` | Client summary line, "81 vulnerabilities" | V8 | 4.2 |
| `pocs/V10/V10-headers-before.txt` | No CSP, HSTS, X-Frame-Options, X-Content-Type-Options; X-Powered-By present | V10 | Fig 9a, 3.10 |
| `pocs/V10/clickjack-test.html` | Login page renders inside a third-party iframe | V10 | Fig 9c, 3.10 |
| `pocs/V13/V13-exe-as-jpg-before.txt` | Renamed PE executable upload — client-side view (`Connection was reset`) | V13 | Fig 13a, 3.13 |
| `pocs/V13/V13-server-crash-stacktrace.txt` | Server-side proof: unhandled `TypeError` at `upload.js:38` crashes the whole Node process | V13 | 3.13 |
| `pocs/V13/V13-oversize-before.txt` | 500 MB upload not rejected; temp file written pre-validation | V13 | 3.13 |
| `pocs/V13/V13-svg-before.txt` | SVG accepted — stored XSS vector | V13 | 3.13 |
| `pocs/V15/V15-changepassword-no-validation.txt` | 1-character password set with no auth and no validation | V15, V1 | Fig 14e, 3.15 |
| `pocs/V15/V15-register-weak-accepted.txt` | `POST /register` accepts "aaaaaa" directly — no OTP required server-side | V15, V11 | Fig 14a, 3.15 |
| `pocs/V15/V15-register-strong-rejected.txt` | Same endpoint rejects a 29-char passphrase | V15 | Fig 14b, 3.15 |
| `pocs/ODIC/oidc-security-tests.md` | state, nonce, PKCE, replay all enforced | OIDC | Fig 12, 5.4 |

*(Rows for evidence not yet captured are added as each work item's baseline/verify steps
are completed — see each folder's checklist.)*

## Notes for other members

Findings that surfaced from Aman's evidence but belong to someone else's section —
picked up here rather than sent as a message, since the team works independently and
meets only in the final report:

- The Google test account created 19 Sep has `verify: false`, confirming **V11**
  (Thisuri).
- Captured JWTs show `exp - iat = 1,296,000s` = exactly 15 days, confirming **V14**
  (Imadh).
- `pocs/V15/V15-changepassword-no-validation.txt` also demonstrates **V1**
  (unauthenticated password change, no validation at all) — Imadh can cite it directly.
- **`POST /register` has no server-side OTP check at all** — confirmed by calling it
  directly with curl and getting `200 OK` with no OTP ever sent/verified in that
  request. The OTP flow in `client/src/pages/Auth.js` is a frontend-only UX gate;
  nothing on the backend enforces it. Directly relevant to **V11** (Thisuri) — the
  email-verification bypass is not just "`verify: true` is hardcoded on register", it's
  that the whole OTP step can be skipped entirely by any client that doesn't bother
  calling it.
- The `mongoose` advisory GHSA-m7xq-9374-9rvx (CVSS 9.8) in `scans/V8/npm-audit-before.json`
  is a **prerequisite for the V2 NoSQL-injection fix** (Dahami): the installed version's
  `sanitizeFilter` does not handle `$nor` (GHSA-wpg9-53fq-2r8h), so the obvious mitigation
  is unreliable until V8 is upgraded.
- The `cloudinary` advisory GHSA-g4mf-96x5-5m2c (CVSS 8.6, argument injection) is
  reachable from `controllers/upload.js:14→33`, which V13 also hardens — a compound
  V8+V13 finding.
- **V13 turned out to be a full server crash, not just "unrestricted upload".**
  Uploading a renamed executable makes Cloudinary reject the content, which triggers an
  unhandled `TypeError` at `controllers/upload.js:38` (a shadowed `res` variable) and
  crashes the entire Node process — every user's connection drops, not just the
  attacker's. See `pocs/V13/V13-server-crash-stacktrace.txt`. Confirmed live 22 Sep 2026.
- (Minor, unrelated) the same crash log showed
  `Error: Unable to find the session to touch` from `connect-mongo/MongoStore.js:329` —
  the session store tried to refresh a session document that no longer exists in
  MongoDB. Might be relevant to **V12** (Imadh) if session lifecycle is being reworked;
  not independently investigated.

## Team-wide folder layout

This structure is designed so all four members can commit evidence into the same
`docs/` tree without collisions:

```
docs/
├── Aman/              this folder — V8, V10, V13, V15, OIDC
│   ├── scans/V8/
│   ├── pocs/{V10,V13,V15,ODIC}/
│   ├── screenshots/{V8,V10,V13,V15,ODIC}/
│   ├── adr/           architecture decision records (OIDC library choice)
│   ├── diagrams/       OIDC sequence diagram
│   └── logs/aman.md
├── Imadh/             V1, V3, V12, V14 — same V<n>/ subfolder convention
├── Dahami/            V2, V5, V6
├── Thisuri/           V4, V7, V9, V11
├── threat-model.md    DFD + STRIDE (Dahami)
├── route-audit.md     52-route × auth matrix (Imadh)
├── references.md      running bibliography
├── report/            one markdown file per report section, written together
└── appendix-c-commits.txt
```

Each member's folder mirrors this one: `scans/`, `pocs/`, `screenshots/`, `logs/`, each
subdivided by `V<n>/`. Not every category applies to every vulnerability — e.g. only V8
needed `scans/`, only OIDC needed `diagrams/` — so subfolders are created as needed
rather than all up front.
