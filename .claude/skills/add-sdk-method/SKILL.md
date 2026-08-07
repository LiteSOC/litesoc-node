---
name: add-sdk-method
description: Add or modify a method on the LiteSOC Node SDK while preserving cross-SDK parity, type safety, and test coverage. Use when changing the public surface of src/index.ts.
---

# Add / Modify an SDK Method (Node)

Follow these steps in order.

1. **Confirm the contract.** Verify the endpoint, request payload, and response shape against `lsoc_app` (route handlers) and `litesoc-docs`. Do not implement anything the server contract does not define. Remember: the server assigns `severity` and `timestamp`; batches cap at 100 events.
2. **Implement in `src/index.ts`.** Add or update the method on `class LiteSOC`. Keep transport-only behavior — no server-side logic (quota/retention/redaction).
3. **Add types + error mapping.** Extend the exported types/options and map HTTP failures to the existing error classes (`AuthenticationError`, `PlanRestrictedError`, `RateLimitError`, `NotFoundError`, `ValidationError`, `LiteSOCError`).
4. **Add Jest tests** in `src/index.test.ts` for the new/changed behavior — success and error paths. Mock HTTP; use mock keys/PII only.
5. **Run the gate:** `npm run typecheck` + `npm run lint` + `npm run test`.
6. **Sync docs & parity.** Update `litesoc-docs` for any contract-visible change and open parity tasks for **litesoc-python** and **litesoc-php** so all three SDKs match.
7. **Do not publish.** Releasing/version bumping is handled by the root `release-check` skill (which also reconciles version drift).
