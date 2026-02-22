# LiteSOC Node.js SDK

Official Node.js/TypeScript SDK for [LiteSOC](https://www.litesoc.io) - Security event tracking and threat detection.

[![npm version](https://badge.fury.io/js/litesoc.svg)](https://www.npmjs.com/package/litesoc)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔒 **Type-safe** - Full TypeScript support with predefined event types
- ⚡ **Batching** - Automatic event batching to reduce network calls
- 🌐 **Universal** - Works in Node.js, Next.js (Server Side), and Edge runtimes
- 🔄 **Auto-retry** - Automatic retry on network failures
- 🤫 **Silent mode** - Fail silently without crashing your application
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

// Track a login failure
await litesoc.track('auth.login_failed', {
  actor: { id: 'user_123', email: 'user@example.com' },
  userIp: '192.168.1.1',
  metadata: { reason: 'invalid_password' },
});

// Flush remaining events before shutdown
await litesoc.flush();
```

## Configuration

```typescript
const litesoc = new LiteSOC({
  // Required: Your LiteSOC API key
  apiKey: 'your-api-key',

  // Optional: Custom API endpoint (default: https://www.litesoc.io/api/v1/collect)
  endpoint: 'https://www.litesoc.io/api/v1/collect',

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

### Authentication Events

| Event | Description |
|-------|-------------|
| `auth.login_success` | Successful login |
| `auth.login_failed` | Failed login attempt |
| `auth.logout` | User logged out |
| `auth.password_changed` | Password was changed |
| `auth.password_reset_requested` | Password reset requested |
| `auth.password_reset_completed` | Password reset completed |
| `auth.mfa_enabled` | MFA was enabled |
| `auth.mfa_disabled` | MFA was disabled |
| `auth.mfa_challenge_success` | MFA challenge passed |
| `auth.mfa_challenge_failed` | MFA challenge failed |
| `auth.session_created` | New session created |
| `auth.session_revoked` | Session was revoked |

### Authorization Events

| Event | Description |
|-------|-------------|
| `authz.role_assigned` | Role was assigned |
| `authz.role_removed` | Role was removed |
| `authz.role_changed` | Role was changed |
| `authz.permission_granted` | Permission was granted |
| `authz.permission_revoked` | Permission was revoked |
| `authz.access_denied` | Access was denied |
| `authz.access_granted` | Access was granted |

### Admin Events (Critical)

| Event | Description |
|-------|-------------|
| `admin.privilege_escalation` | Privilege escalation detected |
| `admin.user_impersonation` | Admin impersonated a user |
| `admin.settings_changed` | System settings changed |
| `admin.api_key_created` | API key was created |
| `admin.api_key_revoked` | API key was revoked |

### Data Events

| Event | Description |
|-------|-------------|
| `data.export` | Data was exported |
| `data.import` | Data was imported |
| `data.bulk_delete` | Bulk data deletion |
| `data.sensitive_access` | Sensitive data accessed |
| `data.download` | File was downloaded |

### Security Events

| Event | Description |
|-------|-------------|
| `security.suspicious_activity` | Suspicious activity detected |
| `security.rate_limit_exceeded` | Rate limit exceeded |
| `security.ip_blocked` | IP was blocked |
| `security.account_locked` | Account was locked |

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

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- 📧 Email: support@litesoc.io
- 📖 Docs: https://www.litesoc.io/docs/api
- 🐛 Issues: https://github.com/LiteSOC/litesoc-node/issues
