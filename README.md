# LiteSOC Node.js SDK

Official Node.js/TypeScript SDK for [LiteSOC](https://www.litesoc.io) - Security event tracking and threat detection.

[![npm version](https://badge.fury.io/js/litesoc.svg)](https://www.npmjs.com/package/litesoc)
[![CI](https://github.com/LiteSOC/litesoc-node/actions/workflows/ci.yml/badge.svg)](https://github.com/LiteSOC/litesoc-node/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/LiteSOC/litesoc-node)
[![ESLint](https://img.shields.io/badge/eslint-passing-brightgreen.svg)](https://github.com/LiteSOC/litesoc-node)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔒 **Type-safe** - Full TypeScript support with 26 predefined standard events
- ⚡ **Batching** - Automatic event batching to reduce network calls
- 🌐 **Universal** - Works in Node.js, Next.js (Server Side), and Edge runtimes
- 🔄 **Auto-retry** - Automatic retry on network failures
- 🗺️ **Geo-IP Enrichment** - Automatic location data from IP addresses
- 🛡️ **Network Intelligence** - VPN, Tor, Proxy & Datacenter detection
- 📊 **Threat Scoring** - Auto-assigned severity (Low → Critical)
- 📦 **Zero dependencies** - Pure TypeScript, no external dependencies

## Installation

```bash
npm install litesoc
# or
yarn add litesoc
# or
pnpm add litesoc
```

## Quick Start

```typescript
import { LiteSOC } from 'litesoc';

// Initialize the SDK
const litesoc = new LiteSOC({
  apiKey: 'your-api-key',
});

// Track a login failure - LiteSOC auto-enriches with GeoIP & Network Intelligence
await litesoc.track('auth.login_failed', {
  actor: { id: 'user_123', email: 'user@example.com' },
  userIp: '192.168.1.1',  // Required for GeoIP & Network Intelligence
  metadata: { reason: 'invalid_password' },
});

// Flush remaining events before shutdown
await litesoc.flush();
```

## Security Intelligence (Automatic Enrichment)

When you provide `userIp`, LiteSOC automatically enriches your events with:

### 🗺️ Geolocation
- Country & City resolution
- Latitude/Longitude coordinates
- Interactive map visualization in dashboard

### 🛡️ Network Intelligence
- **VPN Detection** - NordVPN, ExpressVPN, Surfshark, etc.
- **Tor Exit Nodes** - Anonymizing network detection
- **Proxy Detection** - HTTP/SOCKS proxy identification
- **Datacenter IPs** - AWS, GCP, Azure, DigitalOcean, etc.

### 📊 Threat Scoring
Events are auto-classified by severity:
- **Low** - Normal activity
- **Medium** - Unusual patterns
- **High** - Suspicious behavior
- **Critical** - Active threats (triggers instant alerts)

> **Important**: Always include `userIp` for full security intelligence features.

## Configuration

```typescript
const litesoc = new LiteSOC({
  // Required: Your LiteSOC API key
  apiKey: 'your-api-key',

  // Optional: Custom API endpoint (default: https://api.litesoc.io/collect)
  endpoint: 'https://api.litesoc.io/collect',

  // Optional: Enable event batching (default: true)
  batching: true,

  // Optional: Batch size before auto-flush (default: 10)
  batchSize: 10,

  // Optional: Batch flush interval in ms (default: 5000)
  flushInterval: 5000,

  // Optional: Enable debug logging (default: false)
  debug: false,

  // Optional: Fail silently on errors (default: true)
  silent: true,

  // Optional: Custom fetch implementation for Edge runtimes
  fetch: customFetch,
});
```

## Usage

### Basic Event Tracking

```typescript
// Track with full options
await litesoc.track('auth.login_failed', {
  actor: { id: 'user_123', email: 'user@example.com' },
  userIp: '192.168.1.1',
  metadata: { reason: 'invalid_password', attempts: 3 },
});

// Track with shorthand actor (just ID)
await litesoc.track('user.created', {
  actor: 'user_456',
  actorEmail: 'newuser@example.com',
});

// Track with custom event type
await litesoc.track('custom.event_type', {
  actor: 'system',
  metadata: { custom_field: 'value' },
});
```

### Convenience Methods

```typescript
// Login events
await litesoc.trackLoginFailed('user_123', { userIp: '192.168.1.1' });
await litesoc.trackLoginSuccess('user_123', { userIp: '192.168.1.1' });

// Security events
await litesoc.trackPrivilegeEscalation('user_123', { 
  userIp: '192.168.1.1' 
});

// Data events
await litesoc.trackSensitiveAccess('user_123', 'users.ssn', { 
  userIp: '192.168.1.1' 
});

await litesoc.trackBulkDelete('user_123', 1000, { 
  metadata: { table: 'orders' } 
});

// Authorization events
await litesoc.trackRoleChanged('user_123', 'user', 'admin', {
  userIp: '192.168.1.1',
});

await litesoc.trackAccessDenied('user_123', '/admin/settings', {
  userIp: '192.168.1.1',
});
```

### Batching

Events are automatically batched to reduce network calls:

```typescript
// These will be batched together
litesoc.track('auth.login_failed', { actor: 'user_1' });
litesoc.track('auth.login_failed', { actor: 'user_2' });
litesoc.track('auth.login_failed', { actor: 'user_3' });

// Manually flush when needed
await litesoc.flush();

// Check queue size
console.log(litesoc.getQueueSize()); // 0

// Clear queue without sending
litesoc.clearQueue();
```

### Graceful Shutdown

```typescript
// Flush remaining events before shutdown
process.on('beforeExit', async () => {
  await litesoc.shutdown();
});

// Or in Next.js API routes
export async function POST(request: Request) {
  // ... your logic
  
  await litesoc.track('api.request', { ... });
  await litesoc.flush(); // Ensure events are sent before response
  
  return Response.json({ success: true });
}
```

## Event Types

LiteSOC supports **26 standard events** across 5 categories. All events are automatically normalized and enriched.

### Authentication Events (8)

| Event | Description | Severity |
|-------|-------------|----------|
| `auth.login_success` | Successful login | Info |
| `auth.login_failed` | Failed login attempt | Info |
| `auth.logout` | User logged out | Info |
| `auth.password_reset` | Password reset requested/completed | Info |
| `auth.mfa_enabled` | MFA was enabled | Info |
| `auth.mfa_disabled` | MFA was disabled | Medium |
| `auth.session_expired` | Session timed out | Info |
| `auth.token_refreshed` | Auth token renewed | Info |

### Authorization Events (4)

| Event | Description | Severity |
|-------|-------------|----------|
| `authz.access_denied` | User denied access to resource | **Critical** |
| `authz.role_changed` | User role/permissions modified | **Critical** |
| `authz.permission_granted` | New permission assigned | Info |
| `authz.permission_revoked` | Permission removed | Medium |

### Admin Events (7)

| Event | Description | Severity |
|-------|-------------|----------|
| `admin.user_created` | New user account created | Info |
| `admin.user_deleted` | User account removed | Medium |
| `admin.user_suspended` | User account disabled | Medium |
| `admin.privilege_escalation` | User gained elevated permissions | **Critical** |
| `admin.settings_changed` | System settings modified | Info |
| `admin.api_key_created` | New API key generated | Info |
| `admin.api_key_revoked` | API key disabled/deleted | Medium |

### Data Events (3)

| Event | Description | Severity |
|-------|-------------|----------|
| `data.export` | Data exported from system | Info |
| `data.bulk_delete` | Large-scale data deletion | **Critical** |
| `data.sensitive_access` | Access to sensitive/private data | **Critical** |

### Security Events (4)

| Event | Description | Severity |
|-------|-------------|----------|
| `security.suspicious_activity` | Anomalous behavior detected | **Critical** |
| `security.rate_limit_exceeded` | API rate limit hit | Medium |
| `security.ip_blocked` | IP blocked due to suspicious activity | Medium |
| `security.brute_force_detected` | Multiple failed login attempts | **Critical** |

## Next.js Integration

### Server Components / API Routes

```typescript
// app/api/login/route.ts
import { LiteSOC } from 'litesoc';
import { headers } from 'next/headers';

const litesoc = new LiteSOC({ 
  apiKey: process.env.LITESOC_API_KEY!,
  batching: false, // Disable batching for API routes
});

export async function POST(request: Request) {
  const headersList = headers();
  const userIp = headersList.get('x-forwarded-for')?.split(',')[0] || 
                 headersList.get('x-real-ip') || 
                 'unknown';
  
  const { email, password } = await request.json();
  
  try {
    // Your login logic...
    const user = await authenticate(email, password);
    
    await litesoc.track('auth.login_success', {
      actor: { id: user.id, email: user.email },
      userIp,
    });
    
    return Response.json({ success: true });
  } catch (error) {
    await litesoc.track('auth.login_failed', {
      actor: email,
      userIp,
      metadata: { reason: error.message },
    });
    
    return Response.json({ error: 'Invalid credentials' }, { status: 401 });
  }
}
```

### Edge Runtime

```typescript
// app/api/edge/route.ts
import { LiteSOC } from 'litesoc';

export const runtime = 'edge';

const litesoc = new LiteSOC({ 
  apiKey: process.env.LITESOC_API_KEY!,
  batching: false,
});

export async function GET(request: Request) {
  const userIp = request.headers.get('cf-connecting-ip') || 'unknown';
  
  await litesoc.track('api.request', {
    userIp,
    metadata: { path: '/api/edge' },
  });
  
  return Response.json({ hello: 'world' });
}
```

## Express.js Integration

```typescript
import express from 'express';
import { LiteSOC } from 'litesoc';

const app = express();
const litesoc = new LiteSOC({ apiKey: process.env.LITESOC_API_KEY! });

// Middleware to track all requests
app.use((req, res, next) => {
  litesoc.track('api.request', {
    userIp: req.ip,
    metadata: { 
      method: req.method, 
      path: req.path,
      userAgent: req.get('user-agent'),
    },
  });
  next();
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  await litesoc.shutdown();
  process.exit(0);
});
```

## Error Handling

By default, the SDK operates in silent mode - errors are logged but don't crash your application:

```typescript
// Silent mode (default)
const litesoc = new LiteSOC({ 
  apiKey: 'invalid-key',
  silent: true, // Errors are logged, not thrown
});

// Strict mode - errors are thrown
const litesocStrict = new LiteSOC({ 
  apiKey: 'invalid-key',
  silent: false, // Errors are thrown
});

try {
  await litesocStrict.track('auth.login_failed', { actor: 'user_123' });
} catch (error) {
  console.error('Failed to track event:', error);
}
```

## TypeScript

The SDK is written in TypeScript and provides full type definitions:

```typescript
import { 
  LiteSOC, 
  LiteSOCOptions,
  EventType,
  TrackOptions,
  Actor,
  AuthEvent,
  SecurityEvent,
  // ... and more
} from 'litesoc';

// Type-safe event names
const event: EventType = 'auth.login_failed'; // ✅
const invalid: EventType = 'invalid'; // ❌ Type error

// Custom events are also supported
const custom: EventType = 'my.custom_event'; // ✅
```

## Development

### Prerequisites

- Node.js 18+ 
- npm, yarn, or pnpm

### Setup

```bash
# Clone the repository
git clone https://github.com/LiteSOC/litesoc-node.git
cd litesoc-node

# Install dependencies
npm install
```

### Scripts

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint

# Fix lint errors
npm run lint:fix

# Type check
npm run typecheck

# Build for production
npm run build

# Build in watch mode (development)
npm run dev
```

### Testing

The SDK uses Jest for testing with 100% code coverage:

```bash
# Run all tests
npm test

# Run tests with coverage report
npm run test:coverage

# Watch mode for development
npm run test:watch
```

### Code Quality

```bash
# ESLint
npm run lint

# Fix auto-fixable issues
npm run lint:fix

# TypeScript type checking
npm run typecheck
```

### Building

```bash
# Build ESM, CJS, and TypeScript declarations
npm run build

# Output:
# - dist/index.js      (CommonJS)
# - dist/index.mjs     (ESM)
# - dist/index.d.ts    (TypeScript declarations)
```

### CI/CD

The project uses GitHub Actions for continuous integration:

- **Lint**: ESLint checks on every push
- **Test**: Jest tests with coverage on Node.js 18.x and 20.x
- **Build**: TypeScript compilation verification
- **Coverage**: 100% code coverage requirement

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- 📧 Email: support@litesoc.io
- 📖 Docs: https://www.litesoc.io/docs/api
- 🐛 Issues: https://github.com/LiteSOC/litesoc-node/issues
