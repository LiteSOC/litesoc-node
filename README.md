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

## Plan Awareness

The SDK is fully plan-aware and provides visibility into your LiteSOC subscription tier, retention limits, and feature availability.

### Checking Your Plan

```typescript
// Get your current plan information
const plan = await litesoc.getPlanInfo();

console.log(`Plan: ${plan.plan}`);           // 'free', 'pro', or 'enterprise'
console.log(`Retention: ${plan.retentionDays} days`);
console.log(`Oldest data: ${plan.cutoffDate}`);

// Check feature availability
if (plan.hasManagementApi) {
  // Pro/Enterprise: Can use getAlerts, resolveAlert, etc.
  const { data: alerts } = await litesoc.getAlerts({ status: 'open' });
}

if (plan.hasBehavioralAi) {
  // Pro/Enterprise: Impossible Travel, Geo-Anomaly detection enabled
  console.log('Behavioral AI features available');
}
```

### Plan Tiers

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Event Ingestion | ✅ | ✅ | ✅ |
| Retention | 7 days | 30 days | 90 days |
| Management API | ❌ | ✅ | ✅ |
| Behavioral AI | ❌ | ✅ | ✅ |
| Alerts | ❌ | ✅ | ✅ |
| Priority Support | ❌ | ❌ | ✅ |

### Response Metadata

All Management API methods return plan metadata in the response:

```typescript
const { data, metadata } = await litesoc.getAlerts({ status: 'open' });

console.log(`Plan: ${metadata.plan}`);
console.log(`Retention: ${metadata.retentionDays} days`);
console.log(`Cutoff: ${metadata.cutoffDate}`);

// Access the actual alerts
for (const alert of data.data) {
  console.log(`${alert.title} - ${alert.severity}`);
}
```

### Plan-Restricted Features

Calling Management API methods on the Free plan will throw a `PlanRestrictedError`:

```typescript
import { LiteSOC, PlanRestrictedError } from 'litesoc';

const litesoc = new LiteSOC({ apiKey: 'free-plan-key' });

try {
  await litesoc.getAlerts();
} catch (error) {
  if (error instanceof PlanRestrictedError) {
    console.log(error.message);
    // "This feature requires a Pro or Enterprise plan. 
    //  Upgrade at https://www.litesoc.io/pricing"
  }
}
```

## Critical: The `userIp` Parameter

> ⚠️ **CRITICAL**: Always provide the real end-user IP address!

The `userIp` parameter is **required** for LiteSOC's most powerful features:

### What `userIp` Enables

| Feature | Without `userIp` | With `userIp` |
|---------|------------------|---------------|
| **Impossible Travel** | ❌ Disabled | ✅ Detects logins from impossible locations |
| **Geo-Anomaly** | ❌ Disabled | ✅ Detects unusual geographic patterns |
| **Forensic Maps** | ❌ No location | ✅ Visual threat maps |
| **Network Intelligence** | ❌ No data | ✅ VPN/Tor/Proxy detection |
| **IP Reputation** | ❌ No scoring | ✅ Threat scoring |

### How to Get the Real IP

```typescript
// Express.js
app.use((req, res, next) => {
  // Get real IP behind proxy/load balancer
  const userIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
              || req.headers['x-real-ip'] 
              || req.ip;
  
  await litesoc.track('auth.login_success', {
    actor: userId,
    userIp,  // ← Required for Behavioral AI
  });
});

// Next.js API Route
import { headers } from 'next/headers';

const headersList = headers();
const userIp = headersList.get('x-forwarded-for')?.split(',')[0] 
            || headersList.get('x-real-ip') 
            || 'unknown';

// Cloudflare Workers / Vercel Edge
const userIp = request.headers.get('cf-connecting-ip') 
            || request.headers.get('x-real-ip')
            || 'unknown';
```

### What Happens Without `userIp`

Events tracked without `userIp` will:
- Have `network_intelligence: null`
- Have `geolocation: null`
- Not trigger Impossible Travel or Geo-Anomaly alerts
- Not appear on Forensic Maps

## Configuration

```typescript
const litesoc = new LiteSOC({
  // Required: Your LiteSOC API key
  apiKey: 'your-api-key',

  // Optional: Custom API base URL (default: https://api.litesoc.io)
  baseUrl: 'https://api.litesoc.io',

  // Optional: Enable event batching (default: true)
  batching: true,

  // Optional: Batch size before auto-flush (default: 10)
  batchSize: 10,

  // Optional: Batch flush interval in ms (default: 5000)
  flushInterval: 5000,

  // Optional: Request timeout in ms (default: 5000)
  timeout: 5000,

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

## API Reference

The SDK provides methods for three main API endpoints:

| Endpoint | Method | SDK Method | Plan |
|----------|--------|------------|------|
| `/collect` | POST | `track()` | All |
| `/events` | GET | `getEvents()`, `getEvent()` | All |
| `/alerts` | GET/PATCH | `getAlerts()`, `getAlert()`, `resolveAlert()`, `markAlertSafe()` | Pro/Enterprise |

---

### Event Collection (`/collect`)

Track security events from your application. Events are automatically enriched with GeoIP and network intelligence.

#### `track(eventName, options?)`

```typescript
// Full example with all options
await litesoc.track('auth.login_failed', {
  actor: { id: 'user_123', email: 'user@example.com' },
  userIp: '192.168.1.1',  // Required for GeoIP & Network Intelligence
  metadata: { 
    reason: 'invalid_password',
    attempts: 3,
    browser: 'Chrome 120'
  },
  timestamp: new Date(),  // Optional, defaults to now
});

// Minimal example
await litesoc.track('auth.logout', {
  actor: 'user_123',
});

// Custom event type
await litesoc.track('billing.subscription_upgraded', {
  actor: 'user_123',
  metadata: { plan: 'pro', previous_plan: 'free' },
});
```

#### Convenience Methods

```typescript
// Authentication
await litesoc.trackLoginFailed('user_123', { userIp: '192.168.1.1' });
await litesoc.trackLoginSuccess('user_123', { userIp: '192.168.1.1' });

// Security
await litesoc.trackPrivilegeEscalation('user_123', { userIp: '192.168.1.1' });
await litesoc.trackAccessDenied('user_123', '/admin/settings', { userIp: '192.168.1.1' });

// Data
await litesoc.trackSensitiveAccess('user_123', 'users.ssn', { userIp: '192.168.1.1' });
await litesoc.trackBulkDelete('user_123', 1000, { metadata: { table: 'orders' } });

// Authorization
await litesoc.trackRoleChanged('user_123', 'user', 'admin', { userIp: '192.168.1.1' });
```

---

### Events API (`/events`)

Query historical security events. Available on all plans with retention limits:
- **Free**: 7 days, max 100 per request
- **Pro**: 30 days, max 100 per request  
- **Enterprise**: 90 days, max 100 per request

#### `getEvents(options?)`

```typescript
// Get recent events with filters
const { data, metadata } = await litesoc.getEvents({
  eventName: 'auth.login_failed',  // Filter by event type
  actorId: 'user_123',             // Filter by actor
  severity: 'critical',            // Filter by severity: 'info' | 'warning' | 'critical'
  limit: 50,                       // Max results (default: 50, max: 100)
  offset: 0,                       // Pagination offset
});

console.log(`Plan: ${metadata.plan}`);
console.log(`Retention: ${metadata.retentionDays} days`);
console.log(`Found ${data.total} events`);

// Iterate through events
for (const event of data.data) {
  console.log(`${event.event_name} by ${event.actor_id} from ${event.user_ip}`);
  console.log(`  Country: ${event.country_code}, City: ${event.city}`);
  console.log(`  VPN: ${event.is_vpn}, Tor: ${event.is_tor}`);
}

// Pagination example
let offset = 0;
const limit = 50;
let hasMore = true;

while (hasMore) {
  const { data } = await litesoc.getEvents({ limit, offset });
  
  for (const event of data.data) {
    // Process event...
  }
  
  hasMore = data.has_more;
  offset += limit;
}
```

#### `getEvent(eventId)`

```typescript
// Get a specific event by ID
const { data: event, metadata } = await litesoc.getEvent('evt_abc123');

console.log(`Event: ${event.event_name}`);
console.log(`Actor: ${event.actor_id}`);
console.log(`IP: ${event.user_ip}`);
console.log(`Location: ${event.city}, ${event.country_code}`);
console.log(`Severity: ${event.severity}`);
console.log(`Created: ${event.created_at}`);

// Network intelligence (Pro/Enterprise only, null for Free)
if (event.is_vpn !== null) {
  console.log(`VPN: ${event.is_vpn}`);
  console.log(`Tor: ${event.is_tor}`);
  console.log(`Proxy: ${event.is_proxy}`);
  console.log(`Datacenter: ${event.is_datacenter}`);
}
```

---

### Alerts API (`/alerts`)

Manage security alerts generated by LiteSOC's threat detection. **Requires Pro or Enterprise plan.**

#### `getAlerts(options?)`

```typescript
import { PlanRestrictedError } from 'litesoc';

try {
  const { data, metadata } = await litesoc.getAlerts({
    status: 'open',           // 'open' | 'acknowledged' | 'resolved' | 'dismissed'
    severity: 'critical',     // 'low' | 'medium' | 'high' | 'critical'
    alertType: 'brute_force_attack',  // Filter by alert type
    limit: 100,               // Max results (default: 100, max: 500)
    offset: 0,                // Pagination offset
  });

  console.log(`Plan: ${metadata.plan}`);
  console.log(`Found ${data.total} alerts`);

  for (const alert of data.data) {
    console.log(`[${alert.severity}] ${alert.title}`);
    console.log(`  Type: ${alert.alert_type}`);
    console.log(`  Status: ${alert.status}`);
    console.log(`  Source IP: ${alert.source_ip}`);
    console.log(`  Actor: ${alert.actor_id}`);
    
    // Forensics data (Pro/Enterprise only)
    if (alert.forensics) {
      console.log(`  Location: ${alert.forensics.location.city}, ${alert.forensics.location.country_code}`);
      console.log(`  VPN: ${alert.forensics.network.is_vpn}`);
      console.log(`  ISP: ${alert.forensics.network.isp}`);
    }
  }
} catch (error) {
  if (error instanceof PlanRestrictedError) {
    console.log('Alerts API requires Pro or Enterprise plan');
  }
}
```

#### Alert Types

| Type | Description |
|------|-------------|
| `impossible_travel` | Login from geographically impossible locations |
| `brute_force_attack` | Multiple failed login attempts |
| `geo_anomaly` | Unusual geographic login pattern |
| `new_device` | Login from previously unseen device |
| `privilege_escalation` | User gained elevated permissions |
| `data_exfiltration` | Unusual data export detected |
| `suspicious_activity` | Generic suspicious behavior |
| `rate_limit_exceeded` | API rate limit violations |

#### `getAlert(alertId)`

```typescript
// Get a specific alert with full forensic details
const { data: alert, metadata } = await litesoc.getAlert('alert_abc123');

console.log(`Alert: ${alert.title}`);
console.log(`Type: ${alert.alert_type}`);
console.log(`Severity: ${alert.severity}`);
console.log(`Status: ${alert.status}`);
console.log(`Description: ${alert.description}`);
console.log(`Source IP: ${alert.source_ip}`);
console.log(`Actor: ${alert.actor_id}`);
console.log(`Trigger Event: ${alert.trigger_event_id}`);
console.log(`Created: ${alert.created_at}`);

// Full forensics (Pro/Enterprise only)
if (alert.forensics) {
  const { network, location } = alert.forensics;
  
  console.log('Network Intelligence:');
  console.log(`  VPN: ${network.is_vpn}`);
  console.log(`  Tor: ${network.is_tor}`);
  console.log(`  Proxy: ${network.is_proxy}`);
  console.log(`  Datacenter: ${network.is_datacenter}`);
  console.log(`  ASN: ${network.asn} (${network.asn_org})`);
  console.log(`  ISP: ${network.isp}`);
  
  console.log('Location:');
  console.log(`  ${location.city}, ${location.region}`);
  console.log(`  ${location.country_name} (${location.country_code})`);
  console.log(`  Coordinates: ${location.latitude}, ${location.longitude}`);
  console.log(`  Timezone: ${location.timezone}`);
}
```

#### `resolveAlert(alertId, resolutionType, options?)`

Mark an alert as resolved after investigation.

```typescript
// Resolution types: 'blocked_ip' | 'reset_password' | 'contacted_user' | 'false_positive' | 'other'

const { data: result } = await litesoc.resolveAlert(
  'alert_abc123',
  'blocked_ip',
  {
    notes: 'Blocked IP 192.168.1.100 at firewall',
    resolvedBy: 'admin@example.com'
  }
);

console.log(`Alert ${result.id} resolved`);
console.log(`Status: ${result.status}`);  // 'resolved'
console.log(`Action: ${result.action}`);  // 'resolve'
console.log(`Resolution Type: ${result.resolution_type}`);
console.log(`Resolved At: ${result.resolved_at}`);
console.log(`Resolved By: ${result.resolved_by}`);

// Minimal example (defaults to 'other' resolution type)
await litesoc.resolveAlert('alert_abc123');
```

#### `markAlertSafe(alertId, options?)`

Mark an alert as safe (false positive/dismissed).

```typescript
// With notes (string shorthand for backward compatibility)
const { data: result } = await litesoc.markAlertSafe(
  'alert_abc123',
  'User was traveling for business - verified by HR'
);

console.log(`Alert ${result.id} marked safe`);
console.log(`Status: ${result.status}`);  // 'dismissed'
console.log(`Action: ${result.action}`);  // 'mark_safe'

// With options object
await litesoc.markAlertSafe('alert_abc123', {
  notes: 'Known VPN usage for remote work',
  markedSafeBy: 'security@example.com'
});

// Without notes
await litesoc.markAlertSafe('alert_abc123');
```

---

### Error Handling

All API methods can throw typed errors:

```typescript
import {
  LiteSOC,
  LiteSOCError,
  AuthenticationError,
  PlanRestrictedError,
  RateLimitError,
  NotFoundError,
  ValidationError,
} from 'litesoc';

try {
  await litesoc.getAlerts();
} catch (error) {
  if (error instanceof AuthenticationError) {
    // 401 - Invalid API key
    console.log('Invalid API key');
  } else if (error instanceof PlanRestrictedError) {
    // 403 - Feature requires upgrade
    console.log('Upgrade to Pro for this feature');
  } else if (error instanceof RateLimitError) {
    // 429 - Too many requests
    console.log(`Rate limited. Retry in ${error.retryAfter} seconds`);
  } else if (error instanceof NotFoundError) {
    // 404 - Resource not found
    console.log('Alert not found');
  } else if (error instanceof ValidationError) {
    // 400 - Invalid request
    console.log(`Invalid request: ${error.message}`);
  } else if (error instanceof LiteSOCError) {
    // Other API error
    console.log(`API error: ${error.message} (${error.statusCode})`);
  }
}
```

---

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
  // Plan awareness types
  ResponseMetadata,
  ApiResponse,
  PlanInfo,
  // Error classes
  LiteSOCError,
  PlanRestrictedError,
  AuthenticationError,
  RateLimitError,
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
