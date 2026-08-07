# CLAUDE.md — litesoc-node

> Complements the workspace root [`../CLAUDE.md`](../CLAUDE.md). The root defines shared agents (`integration-reviewer`, `backend`, `security`, `test-runner`, `bug-investigator`, …), rules, and skills — this file does **not** redefine them. Read the root first for cross-repo standards.

## Purpose
Official LiteSOC **Node/TypeScript SDK** (npm package `litesoc`). Thin, typed client over the LiteSOC HTTP API for ingestion (`POST /collect`) and management (`/alerts`, `/events`). It must stay at **100% behavioral parity** with `litesoc-python` and `litesoc-php` and in sync with the `lsoc_app` API contract and `litesoc-docs`.

## Technology stack
- **Language:** TypeScript `^5.7`, targets **Node >=18**.
- **Build:** tsup `^8.3` → dual **ESM + CJS + type declarations** in `dist/`.
- **Test:** Jest `^29.7` + ts-jest.
- **Lint:** ESLint `^9.39`.

## Key directories
- `src/` — `index.ts` (entire SDK surface) and `index.test.ts`.
- `dist/` — build output (generated; do not edit).

## Commands
| Task | Command |
| --- | --- |
| Build | `npm run build` (`tsup`) |
| Watch | `npm run dev` (`tsup --watch`) |
| Test | `npm run test` (`jest`) |
| Coverage | `npm run test:coverage` (`jest --coverage`) |
| Lint | `npm run lint` (`eslint src/`) |
| Lint fix | `npm run lint:fix` (`eslint src/ --fix`) |
| Typecheck | `npm run typecheck` (`tsc --noEmit`) |

Before any commit run: `npm run typecheck` + `npm run lint` + `npm run test`.

## Architecture & boundaries
- Entry: `class LiteSOC`, factory `createLiteSOC()`, plus a default export.
- **Methods:** `track`, `trackBatch`, `flush`, `getAlerts`, `getAlert`, `resolveAlert`, `markAlertSafe`, `getEvents`, `getEvent`, `getQueueSize`, `clearQueue`, `shutdown`, `getPlanInfo`.
- **Convenience helpers:** `trackLoginFailed`, `trackLoginSuccess`, `trackPrivilegeEscalation`, `trackSensitiveAccess`, `trackBulkDelete`, `trackRoleChanged`, `trackAccessDenied`.
- **Error classes:** `LiteSOCError`, `AuthenticationError`, `PlanRestrictedError`, `RateLimitError`, `NotFoundError`, `ValidationError`.
- **Constants:** `SDK_VERSION`, `DEFAULT_BASE_URL`, `USER_AGENT`.
- **Client boundary:** the SDK is transport + typing only. Server assigns `severity` and `timestamp`; quota, retention, and redaction are **server concerns** and must never be reimplemented here. Batches are capped at **100 events**.

## External dependencies
- HTTP API base `https://api.litesoc.io`, authenticated with the `X-API-Key` header.
- Response headers surfaced to callers: `X-LiteSOC-Plan`, `X-LiteSOC-Retention`, `X-LiteSOC-Cutoff`.

## Environment variables
None read in `src/`. All configuration is passed through `LiteSOCOptions` (constructor options). Do not add hidden `process.env` reads.

## Security-sensitive code paths
- API-key handling / `X-API-Key` header construction and the `USER_AGENT`/`SDK_VERSION` metadata sent to the server.
- Error mapping (auth vs. rate-limit vs. plan-restricted) — must not leak key material into messages or logs.
- Tests must use mock HTTP and mock credentials only (e.g. `lsoc_live_mockkey`); never real keys or PII.

## Database / migration responsibility
None. SDKs own no schema or migrations.

## Deployment / registry target
- **npm** package `litesoc`. Manifest version **2.5.1**.
- ⚠️ **Version drift:** in-code `SDK_VERSION` is **2.5.0** vs manifest **2.5.1**. Reconcile manifest + `SDK_VERSION` + `USER_AGENT` + `CHANGELOG.md` during any release (`release-check`).
- CI: `.github/workflows/ci.yml` (lint, test matrix Node 18/20/22 with coverage, typecheck, build).
- **No publish workflow** — publishing is manual (`npm publish`); `prepublishOnly` runs the build.

## Cross-repository consumers & dependencies
- Consumed by **litesoc-mcp** (npm dependency `litesoc`).
- Parity peers: **litesoc-python**, **litesoc-php**. Contract source of truth: **lsoc_app** + **litesoc-docs**.

## Repo-specific rules & skills
- Rule: [`.claude/rules/sdk-contract.md`](.claude/rules/sdk-contract.md) — parity, versioning, and testing constraints.
- Skill: [`.claude/skills/add-sdk-method/SKILL.md`](.claude/skills/add-sdk-method/SKILL.md) — workflow to add or modify an SDK method.
- Cross-repo/integration/testing/security concerns follow the **root** rules and agents.
