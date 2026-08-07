---
title: LiteSOC Node SDK Contract
scope: litesoc-node
applies_to:
  - "src/**"
  - "package.json"
  - "CHANGELOG.md"
---

# SDK Contract Rule (Node)

- **Transport & auth:** API base `https://api.litesoc.io`, authenticate with the `X-API-Key` header. Do not invent alternate auth.
- **Parity:** Keep the method surface and behavior at 100% parity with `litesoc-python` and `litesoc-php`. Any change here opens parity tasks for both.
- **No server logic:** Never embed server-only concerns in the client — `severity`, `timestamp`, quota enforcement, retention, and redaction are assigned/enforced by the server.
- **Contract source of truth:** Confirm request/response shapes against `lsoc_app` and update `litesoc-docs` on any contract change.
- **Versioning:** On release, bump consistently across the manifest (`package.json`), the in-code `SDK_VERSION` constant, and `USER_AGENT`, and update `CHANGELOG.md`. (Known drift: manifest `2.5.1` vs `SDK_VERSION` `2.5.0` — reconcile.)
- **Testing:** Add a Jest test for every method. Mock all HTTP; never use real API keys or PII (use `lsoc_live_mockkey`, `test@example.com`).
- **Gate:** Before commit/PR run `npm run typecheck` + `npm run lint` + `npm run test`.
- **Publishing** is gated by the root `release-check` skill — do not publish ad hoc.
