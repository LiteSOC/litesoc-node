# Changelog

All notable changes to the LiteSOC Node.js SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-02-26

### Added
- **Request Timeout** - Added configurable `timeout` option (default: 10 seconds)
  - Prevents SDK from blocking client applications if LiteSOC API is slow
  - Uses `AbortController` for reliable timeout handling
  - Timed-out events are automatically re-queued for retry

### Changed
- `sendEvents()` method now includes `AbortController` with timeout signal
- Added `X-LiteSOC-Retry-Count` header to track retry attempts

### Fixed
- SDK no longer blocks indefinitely if API is unresponsive
- Improved non-blocking behavior for production applications

### Notes
- Default timeout is 10 seconds, configurable via `timeout` option
- Combined with `silent: true` (default), SDK never blocks or throws in production
- Events that timeout are re-queued up to 3 times before being dropped

## [1.2.1] - 2026-02-25

### Fixed
- Fixed TypeScript type compatibility for mock fetch in tests

## [1.2.0] - 2026-02-25

### Changed
- **New API Endpoint** - Updated default endpoint from `https://litesoc.io/api/v1/collect` to `https://api.litesoc.io/collect`
  - Cleaner subdomain-based API architecture
  - Improved routing and performance
  - No breaking changes - existing custom endpoints continue to work

### Notes
- If you're using a custom `endpoint` option, no changes needed
- The new endpoint provides the same functionality with improved infrastructure

## [1.1.0] - 2026-02-22

### Added
- **26 Standard Security Events** - Reorganized event types into 5 categories:
  - Auth (8 events): `login_success`, `login_failed`, `logout`, `password_reset`, `mfa_enabled`, `mfa_disabled`, `session_expired`, `token_refreshed`
  - Authz (4 events): `role_changed`, `permission_granted`, `permission_revoked`, `access_denied`
  - Admin (7 events): `privilege_escalation`, `user_impersonation`, `settings_changed`, `api_key_created`, `api_key_revoked`, `user_suspended`, `user_deleted`
  - Data (3 events): `bulk_delete`, `sensitive_access`, `export`
  - Security (4 events): `suspicious_activity`, `rate_limit_exceeded`, `ip_blocked`, `brute_force_detected`
- **Security Intelligence Documentation** - Added documentation for auto-enrichment features:
  - GeoIP Enrichment (country, city, coordinates)
  - Network Intelligence (VPN, Tor, Proxy, Datacenter detection)
  - Threat Scoring (Low → Critical severity auto-classification)
- New TypeScript types: `AuthEvent`, `AuthzEvent`, `AdminEvent`, `DataEvent`, `SecurityEvent`

### Changed
- Reorganized event type definitions with standard events as primary types
- Updated README with Security Intelligence section and 26-event table
- Emphasized importance of `user_ip` parameter for full enrichment features

### Deprecated
- Legacy event types moved to `LegacySecurityEvent` (still supported for backward compatibility)

## [1.0.2] - Previous Release

- Initial stable release with basic event tracking
