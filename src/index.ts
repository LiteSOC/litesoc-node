/**
 * LiteSOC Node.js/TypeScript SDK v2.0.0
 * Official SDK for security event tracking and threat detection
 *
 * Features:
 * - Event ingestion (all plans)
 * - Management API: getAlerts, resolveAlert, getEvents (Pro/Enterprise)
 * - Automatic batching and retry
 * - TypeScript support with strict types
 *
 * @packageDocumentation
 */

// ============================================
// CONSTANTS
// ============================================

/** SDK version */
export const SDK_VERSION = "2.0.0";

/** Default API base URL */
export const DEFAULT_BASE_URL = "https://api.litesoc.io";

/** User-Agent header for all requests */
export const USER_AGENT = `litesoc-node-sdk/${SDK_VERSION}`;

// ============================================
// TYPE DEFINITIONS - 26 STANDARD EVENTS
// ============================================

/** Fetch function type for cross-environment compatibility */
type FetchFunction = (
  input: string | URL | Request,
  init?: RequestInit
) => Promise<Response>;

/**
 * Standard Authentication Events (8)
 * Core auth events for tracking user authentication lifecycle
 */
export type AuthEvent =
  | "auth.login_success"
  | "auth.login_failed"
  | "auth.logout"
  | "auth.password_reset"
  | "auth.mfa_enabled"
  | "auth.mfa_disabled"
  | "auth.session_expired"
  | "auth.token_refreshed";

/**
 * Standard Authorization Events (4)
 * Events for tracking access control changes
 */
export type AuthzEvent =
  | "authz.access_denied"
  | "authz.role_changed"
  | "authz.permission_granted"
  | "authz.permission_revoked";

/**
 * Standard Admin Events (7)
 * Events for tracking administrative actions
 */
export type AdminEvent =
  | "admin.user_created"
  | "admin.user_deleted"
  | "admin.user_suspended"
  | "admin.privilege_escalation"
  | "admin.settings_changed"
  | "admin.api_key_created"
  | "admin.api_key_revoked";

/**
 * Standard Data Events (3)
 * Events for tracking data access and modifications
 */
export type DataEvent = "data.export" | "data.bulk_delete" | "data.sensitive_access";

/**
 * Standard Security Events (4)
 * Events for tracking security-related activities
 */
export type SecurityEvent =
  | "security.suspicious_activity"
  | "security.rate_limit_exceeded"
  | "security.ip_blocked"
  | "security.brute_force_detected";

/**
 * The 26 Standard Security Events
 * These are the core events supported by LiteSOC
 */
export type StandardEventType =
  | AuthEvent
  | AuthzEvent
  | AdminEvent
  | DataEvent
  | SecurityEvent;

/**
 * Custom event type (string pattern: category.action)
 * Use for events not covered by the 26 standard events
 */
export type CustomEventType = `${string}.${string}`;

/**
 * All supported event types (standard + custom)
 */
export type EventType = StandardEventType | CustomEventType;

/**
 * Event severity levels
 */
export type EventSeverity = "info" | "warning" | "critical";

/**
 * Alert severity levels (different from event severity)
 */
export type AlertSeverity = "low" | "medium" | "high" | "critical";

/**
 * Alert status values
 */
export type AlertStatus = "open" | "acknowledged" | "resolved" | "dismissed";

/**
 * Alert type values
 */
export type AlertType =
  | "impossible_travel"
  | "brute_force_attack"
  | "geo_anomaly"
  | "new_device"
  | "privilege_escalation"
  | "data_exfiltration"
  | "suspicious_activity"
  | "rate_limit_exceeded";

/**
 * Actor information
 */
export interface Actor {
  /** Unique identifier for the actor (user ID, API key ID, etc.) */
  id: string;
  /** Actor's email address (optional) */
  email?: string;
}

/**
 * Event metadata (arbitrary key-value pairs)
 */
export type EventMetadata = Record<string, unknown>;

/**
 * Options for tracking an event
 */
export interface TrackOptions {
  /** The actor (user) performing the action */
  actor?: Actor | string;
  /** Actor's email address (shorthand for actor.email) */
  actorEmail?: string;
  /** End-user's IP address (the user making the request) */
  userIp?: string;
  /** Event severity (optional, auto-detected for standard events) */
  severity?: EventSeverity;
  /** Additional metadata for the event */
  metadata?: EventMetadata;
  /** Custom timestamp (defaults to now) */
  timestamp?: Date | string;
}

/**
 * Internal event structure for the queue
 */
interface QueuedEvent {
  event: EventType;
  actor: Actor | null;
  user_ip: string | null;
  metadata: EventMetadata;
  timestamp: string;
}

/**
 * API response structure for event ingestion
 */
interface IngestApiResponse {
  success: boolean;
  event_id?: string;
  events_accepted?: number;
  error?: string;
}

/**
 * Alert object returned from the Management API
 */
export interface Alert {
  id: string;
  alert_type: AlertType;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  description: string | null;
  source_ip: string | null;
  actor_id: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  resolution_notes: string | null;
  metadata: Record<string, unknown>;
}

/**
 * Event object returned from the Management API
 */
export interface Event {
  id: string;
  event_name: string;
  actor_id: string | null;
  actor_email: string | null;
  user_ip: string | null;
  severity: EventSeverity;
  metadata: Record<string, unknown>;
  created_at: string;
}

/**
 * Options for fetching alerts
 */
export interface GetAlertsOptions {
  /** Filter by alert status */
  status?: AlertStatus;
  /** Filter by alert severity */
  severity?: AlertSeverity;
  /** Filter by alert type */
  alertType?: AlertType;
  /** Maximum number of alerts to return (default: 100, max: 500) */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

/**
 * Options for fetching events
 */
export interface GetEventsOptions {
  /** Filter by event name (e.g., 'auth.login_failed') */
  eventName?: string;
  /** Filter by actor ID */
  actorId?: string;
  /** Filter by severity */
  severity?: EventSeverity;
  /** Maximum number of events to return (default: 50, max: 100) */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

/**
 * Paginated response from Management API
 */
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * SDK configuration options
 */
export interface LiteSOCOptions {
  /** Your LiteSOC API key (required) */
  apiKey: string;
  /** Base URL for the API (defaults to https://api.litesoc.io) */
  baseUrl?: string;
  /** Enable batching for event ingestion (defaults to true) */
  batching?: boolean;
  /** Batch size before auto-flush (defaults to 10) */
  batchSize?: number;
  /** Batch flush interval in milliseconds (defaults to 5000ms) */
  flushInterval?: number;
  /** Enable debug logging (defaults to false) */
  debug?: boolean;
  /** Fail silently on errors (defaults to true for ingestion) */
  silent?: boolean;
  /** Custom fetch implementation (for Edge runtimes) */
  fetch?: FetchFunction;
  /** Request timeout in milliseconds (defaults to 5000ms) */
  timeout?: number;
}

// ============================================
// CUSTOM ERROR CLASSES
// ============================================

/**
 * Base error class for LiteSOC SDK errors
 */
export class LiteSOCError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly code?: string
  ) {
    super(message);
    this.name = "LiteSOCError";
  }
}

/**
 * Error thrown when authentication fails (401)
 */
export class AuthenticationError extends LiteSOCError {
  constructor(message = "Invalid API key. Please check your credentials.") {
    super(message, 401, "UNAUTHORIZED");
    this.name = "AuthenticationError";
  }
}

/**
 * Error thrown when the plan doesn't support a feature (403)
 */
export class PlanRestrictedError extends LiteSOCError {
  constructor(
    message = "This feature requires a Pro or Enterprise plan. Upgrade at https://www.litesoc.io/pricing"
  ) {
    super(message, 403, "PLAN_RESTRICTED");
    this.name = "PlanRestrictedError";
  }
}

/**
 * Error thrown when rate limit is exceeded (429)
 */
export class RateLimitError extends LiteSOCError {
  constructor(
    message = "Rate limit exceeded. Please slow down your requests.",
    public readonly retryAfter?: number
  ) {
    super(message, 429, "RATE_LIMIT_EXCEEDED");
    this.name = "RateLimitError";
  }
}

/**
 * Error thrown when a resource is not found (404)
 */
export class NotFoundError extends LiteSOCError {
  constructor(message = "Resource not found") {
    super(message, 404, "NOT_FOUND");
    this.name = "NotFoundError";
  }
}

/**
 * Error thrown for validation errors (400)
 */
export class ValidationError extends LiteSOCError {
  constructor(message: string) {
    super(message, 400, "VALIDATION_ERROR");
    this.name = "ValidationError";
  }
}

// ============================================
// LITESOC SDK CLASS
// ============================================

/**
 * LiteSOC SDK for security event tracking and management
 *
 * The SDK provides two main capabilities:
 * 1. **Event Ingestion** (all plans): Track security events with `track()`
 * 2. **Management API** (Pro/Enterprise): Query alerts and events
 *
 * @example
 * ```typescript
 * import { LiteSOC } from 'litesoc';
 *
 * const litesoc = new LiteSOC({ apiKey: 'your-api-key' });
 *
 * // Track a login failure (all plans)
 * await litesoc.track('auth.login_failed', {
 *   actor: { id: 'user_123', email: 'user@example.com' },
 *   userIp: '192.168.1.1',
 *   metadata: { reason: 'invalid_password' }
 * });
 *
 * // Get alerts (Pro/Enterprise only)
 * const alerts = await litesoc.getAlerts({ status: 'open', severity: 'critical' });
 *
 * // Resolve an alert (Pro/Enterprise only)
 * await litesoc.resolveAlert('alert_123', 'Verified as false positive');
 *
 * // Flush remaining events before shutdown
 * await litesoc.flush();
 * ```
 */
export class LiteSOC {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly batching: boolean;
  private readonly batchSize: number;
  private readonly flushInterval: number;
  private readonly debug: boolean;
  private readonly silent: boolean;
  private readonly fetchFn: FetchFunction;
  private readonly timeout: number;

  private queue: QueuedEvent[] = [];
  private flushTimer: ReturnType<typeof globalThis.setTimeout> | null = null;
  private isFlushing = false;

  /**
   * Create a new LiteSOC SDK instance
   *
   * @param options - SDK configuration options
   * @throws Error if apiKey is not provided
   *
   * @example
   * ```typescript
   * const litesoc = new LiteSOC({
   *   apiKey: 'lsk_...',
   *   debug: true,  // Enable debug logging
   *   batching: true,  // Enable event batching (default)
   * });
   * ```
   */
  constructor(options: LiteSOCOptions) {
    if (!options.apiKey) {
      throw new Error("LiteSOC: apiKey is required");
    }

    this.apiKey = options.apiKey;
    this.baseUrl = options.baseUrl || DEFAULT_BASE_URL;
    this.batching = options.batching ?? true;
    this.batchSize = options.batchSize ?? 10;
    this.flushInterval = options.flushInterval ?? 5000;
    this.debug = options.debug ?? false;
    this.silent = options.silent ?? true;
    this.fetchFn = options.fetch ?? fetch;
    this.timeout = options.timeout ?? 5000;

    // Validate fetch is available
    if (!this.fetchFn) {
      throw new Error(
        "LiteSOC: fetch is not available. Please provide a custom fetch implementation."
      );
    }

    this.log("Initialized with baseUrl:", this.baseUrl);
  }

  // ============================================
  // EVENT INGESTION (ALL PLANS)
  // ============================================

  /**
   * Track a security event
   *
   * This method is available on all plans (Free, Pro, Enterprise).
   * Events are sent to the `/collect` endpoint.
   *
   * @param eventName - The event type. Use one of the 26 standard events
   *   (e.g., 'auth.login_failed') or a custom event in 'category.action' format.
   * @param options - Event options including actor, IP, and metadata
   * @returns Promise that resolves when the event is queued or sent
   *
   * @remarks
   * **Plan availability:** Free, Pro, Enterprise
   *
   * **Standard events (26):**
   * - Auth: login_success, login_failed, logout, password_reset, mfa_enabled, mfa_disabled, session_expired, token_refreshed
   * - Authz: access_denied, role_changed, permission_granted, permission_revoked
   * - Admin: user_created, user_deleted, user_suspended, privilege_escalation, settings_changed, api_key_created, api_key_revoked
   * - Data: export, bulk_delete, sensitive_access
   * - Security: suspicious_activity, rate_limit_exceeded, ip_blocked, brute_force_detected
   *
   * @example
   * ```typescript
   * // Track with full options
   * await litesoc.track('auth.login_failed', {
   *   actor: { id: 'user_123', email: 'user@example.com' },
   *   userIp: '192.168.1.1',
   *   severity: 'warning',
   *   metadata: { reason: 'invalid_password', attempts: 3 }
   * });
   *
   * // Track with shorthand actor
   * await litesoc.track('admin.user_created', {
   *   actor: 'admin_456',
   *   actorEmail: 'admin@example.com'
   * });
   * ```
   */
  async track(eventName: EventType, options: TrackOptions = {}): Promise<void> {
    try {
      // Normalize actor
      let actor: Actor | null = null;
      if (options.actor) {
        if (typeof options.actor === "string") {
          actor = { id: options.actor, email: options.actorEmail };
        } else {
          actor = {
            id: options.actor.id,
            email: options.actor.email || options.actorEmail,
          };
        }
      } else if (options.actorEmail) {
        actor = { id: options.actorEmail, email: options.actorEmail };
      }

      // Build the event
      const event: QueuedEvent = {
        event: eventName,
        actor,
        user_ip: options.userIp || null,
        metadata: {
          ...options.metadata,
          _sdk: "litesoc-node",
          _sdk_version: SDK_VERSION,
          ...(options.severity ? { _severity: options.severity } : {}),
        },
        timestamp:
          options.timestamp instanceof Date
            ? options.timestamp.toISOString()
            : options.timestamp || new Date().toISOString(),
      };

      this.log("Tracking event:", eventName, event);

      if (this.batching) {
        this.queue.push(event);
        this.log(`Event queued. Queue size: ${this.queue.length}`);

        if (this.queue.length >= this.batchSize) {
          await this.flush();
        } else {
          this.scheduleFlush();
        }
      } else {
        await this.sendEvents([event]);
      }
    } catch (error) {
      this.handleError("track", error);
    }
  }

  /**
   * Flush all queued events to the server
   *
   * @returns Promise that resolves when all events are sent
   *
   * @remarks
   * **Plan availability:** Free, Pro, Enterprise
   *
   * @example
   * ```typescript
   * // Flush before application shutdown
   * process.on('beforeExit', async () => {
   *   await litesoc.flush();
   * });
   * ```
   */
  async flush(): Promise<void> {
    if (this.isFlushing) {
      this.log("Flush already in progress, skipping");
      return;
    }

    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    const events = [...this.queue];
    this.queue = [];

    if (events.length === 0) {
      this.log("No events to flush");
      return;
    }

    this.isFlushing = true;
    this.log(`Flushing ${events.length} events`);

    try {
      await this.sendEvents(events);
    } finally {
      this.isFlushing = false;
    }
  }

  // ============================================
  // MANAGEMENT API (PRO/ENTERPRISE ONLY)
  // ============================================

  /**
   * Get security alerts from the Management API
   *
   * Retrieves alerts that have been triggered by LiteSOC's threat detection.
   * Alerts are automatically generated when suspicious patterns are detected.
   *
   * @param options - Filter and pagination options
   * @returns Promise resolving to paginated alert data
   *
   * @remarks
   * **Plan availability:** Pro, Enterprise only
   *
   * Free plan users will receive a `PlanRestrictedError`.
   *
   * @throws {PlanRestrictedError} When called with a Free plan API key
   * @throws {AuthenticationError} When the API key is invalid
   * @throws {RateLimitError} When rate limit is exceeded
   *
   * @example
   * ```typescript
   * // Get all open critical alerts
   * const { data: alerts, total } = await litesoc.getAlerts({
   *   status: 'open',
   *   severity: 'critical',
   *   limit: 50
   * });
   *
   * console.log(`Found ${total} critical alerts`);
   * for (const alert of alerts) {
   *   console.log(`${alert.title} - ${alert.alert_type}`);
   * }
   * ```
   */
  async getAlerts(options: GetAlertsOptions = {}): Promise<PaginatedResponse<Alert>> {
    const params = new URLSearchParams();

    if (options.status) params.append("status", options.status);
    if (options.severity) params.append("severity", options.severity);
    if (options.alertType) params.append("alert_type", options.alertType);
    if (options.limit) params.append("limit", String(options.limit));
    if (options.offset) params.append("offset", String(options.offset));

    const queryString = params.toString();
    const url = `${this.baseUrl}/v1/alerts${queryString ? `?${queryString}` : ""}`;

    const response = await this.makeRequest<PaginatedResponse<Alert>>("GET", url);
    return response;
  }

  /**
   * Get a single alert by ID
   *
   * @param alertId - The unique alert ID
   * @returns Promise resolving to the alert
   *
   * @remarks
   * **Plan availability:** Pro, Enterprise only
   *
   * @throws {PlanRestrictedError} When called with a Free plan API key
   * @throws {NotFoundError} When the alert doesn't exist
   * @throws {AuthenticationError} When the API key is invalid
   *
   * @example
   * ```typescript
   * const alert = await litesoc.getAlert('alert_abc123');
   * console.log(`Alert: ${alert.title} (${alert.status})`);
   * ```
   */
  async getAlert(alertId: string): Promise<Alert> {
    if (!alertId) {
      throw new ValidationError("alertId is required");
    }

    const url = `${this.baseUrl}/v1/alerts/${alertId}`;
    const response = await this.makeRequest<{ data: Alert }>("GET", url);
    return response.data;
  }

  /**
   * Resolve an alert
   *
   * Marks an alert as resolved with optional resolution notes.
   * This is useful for closing alerts after investigation.
   *
   * @param alertId - The unique alert ID to resolve
   * @param notes - Optional resolution notes explaining how the alert was resolved
   * @returns Promise resolving to the updated alert
   *
   * @remarks
   * **Plan availability:** Pro, Enterprise only
   *
   * @throws {PlanRestrictedError} When called with a Free plan API key
   * @throws {NotFoundError} When the alert doesn't exist
   * @throws {AuthenticationError} When the API key is invalid
   *
   * @example
   * ```typescript
   * const alert = await litesoc.resolveAlert(
   *   'alert_abc123',
   *   'Verified as authorized access by admin team'
   * );
   * console.log(`Alert resolved at: ${alert.resolved_at}`);
   * ```
   */
  async resolveAlert(alertId: string, notes?: string): Promise<Alert> {
    if (!alertId) {
      throw new ValidationError("alertId is required");
    }

    const url = `${this.baseUrl}/v1/alerts/${alertId}`;
    const body: Record<string, string> = {
      status: "resolved",
      resolution_type: "resolved",
    };
    if (notes) {
      body.resolution_notes = notes;
    }

    const response = await this.makeRequest<{ data: Alert }>("PATCH", url, body);
    return response.data;
  }

  /**
   * Mark an alert as safe (false positive)
   *
   * Marks an alert as dismissed/safe, indicating it was a false positive.
   *
   * @param alertId - The unique alert ID to mark as safe
   * @param notes - Optional notes explaining why this is a false positive
   * @returns Promise resolving to the updated alert
   *
   * @remarks
   * **Plan availability:** Pro, Enterprise only
   *
   * @throws {PlanRestrictedError} When called with a Free plan API key
   * @throws {NotFoundError} When the alert doesn't exist
   * @throws {AuthenticationError} When the API key is invalid
   *
   * @example
   * ```typescript
   * const alert = await litesoc.markAlertSafe(
   *   'alert_abc123',
   *   'User was traveling for business, confirmed via HR'
   * );
   * ```
   */
  async markAlertSafe(alertId: string, notes?: string): Promise<Alert> {
    if (!alertId) {
      throw new ValidationError("alertId is required");
    }

    const url = `${this.baseUrl}/v1/alerts/${alertId}`;
    const body: Record<string, string> = {
      status: "dismissed",
      resolution_type: "false_positive",
    };
    if (notes) {
      body.resolution_notes = notes;
    }

    const response = await this.makeRequest<{ data: Alert }>("PATCH", url, body);
    return response.data;
  }

  /**
   * Get security events from the Management API
   *
   * Retrieves raw security events (audit logs) that have been tracked.
   * Use this to query historical events for investigation or reporting.
   *
   * @param options - Filter and pagination options
   * @returns Promise resolving to paginated event data
   *
   * @remarks
   * **Plan availability:** Free (limited), Pro, Enterprise
   *
   * - Free plan: 7-day retention, max 100 events per request
   * - Pro plan: 30-day retention, max 100 events per request
   * - Enterprise plan: 90-day retention, max 100 events per request
   *
   * @throws {AuthenticationError} When the API key is invalid
   * @throws {RateLimitError} When rate limit is exceeded
   *
   * @example
   * ```typescript
   * // Get recent failed logins
   * const { data: events } = await litesoc.getEvents({
   *   eventName: 'auth.login_failed',
   *   severity: 'warning',
   *   limit: 50
   * });
   *
   * for (const event of events) {
   *   console.log(`${event.event_name} from ${event.user_ip} at ${event.created_at}`);
   * }
   * ```
   */
  async getEvents(options: GetEventsOptions = {}): Promise<PaginatedResponse<Event>> {
    const params = new URLSearchParams();

    if (options.eventName) params.append("event_name", options.eventName);
    if (options.actorId) params.append("actor_id", options.actorId);
    if (options.severity) params.append("severity", options.severity);
    if (options.limit) params.append("limit", String(options.limit));
    if (options.offset) params.append("offset", String(options.offset));

    const queryString = params.toString();
    const url = `${this.baseUrl}/v1/events${queryString ? `?${queryString}` : ""}`;

    const response = await this.makeRequest<PaginatedResponse<Event>>("GET", url);
    return response;
  }

  /**
   * Get a single event by ID
   *
   * @param eventId - The unique event ID
   * @returns Promise resolving to the event
   *
   * @remarks
   * **Plan availability:** Free (within retention), Pro, Enterprise
   *
   * @throws {NotFoundError} When the event doesn't exist or is outside retention period
   * @throws {AuthenticationError} When the API key is invalid
   *
   * @example
   * ```typescript
   * const event = await litesoc.getEvent('evt_abc123');
   * console.log(`Event: ${event.event_name} by ${event.actor_id}`);
   * ```
   */
  async getEvent(eventId: string): Promise<Event> {
    if (!eventId) {
      throw new ValidationError("eventId is required");
    }

    const url = `${this.baseUrl}/v1/events/${eventId}`;
    const response = await this.makeRequest<{ data: Event }>("GET", url);
    return response.data;
  }

  // ============================================
  // UTILITY METHODS
  // ============================================

  /**
   * Get the current queue size
   *
   * @returns Number of events in the queue
   */
  getQueueSize(): number {
    return this.queue.length;
  }

  /**
   * Clear all queued events without sending
   */
  clearQueue(): void {
    this.queue = [];
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    this.log("Queue cleared");
  }

  /**
   * Shutdown the SDK gracefully
   * Flushes remaining events and clears timers
   */
  async shutdown(): Promise<void> {
    this.log("Shutting down...");
    await this.flush(); // flush() already clears the flushTimer
    this.log("Shutdown complete");
  }

  // ============================================
  // CONVENIENCE METHODS (INGESTION)
  // ============================================

  /**
   * Track a login failure event
   *
   * @remarks **Plan availability:** Free, Pro, Enterprise
   */
  async trackLoginFailed(
    actorId: string,
    options: Omit<TrackOptions, "actor"> = {}
  ): Promise<void> {
    return this.track("auth.login_failed", {
      actor: actorId,
      ...options,
    });
  }

  /**
   * Track a login success event
   *
   * @remarks **Plan availability:** Free, Pro, Enterprise
   */
  async trackLoginSuccess(
    actorId: string,
    options: Omit<TrackOptions, "actor"> = {}
  ): Promise<void> {
    return this.track("auth.login_success", {
      actor: actorId,
      ...options,
    });
  }

  /**
   * Track a privilege escalation event
   *
   * @remarks **Plan availability:** Free, Pro, Enterprise
   */
  async trackPrivilegeEscalation(
    actorId: string,
    options: Omit<TrackOptions, "actor"> = {}
  ): Promise<void> {
    return this.track("admin.privilege_escalation", {
      actor: actorId,
      severity: "critical",
      ...options,
    });
  }

  /**
   * Track a sensitive data access event
   *
   * @remarks **Plan availability:** Free, Pro, Enterprise
   */
  async trackSensitiveAccess(
    actorId: string,
    resource: string,
    options: Omit<TrackOptions, "actor"> = {}
  ): Promise<void> {
    return this.track("data.sensitive_access", {
      actor: actorId,
      metadata: {
        resource,
        ...options.metadata,
      },
      ...options,
    });
  }

  /**
   * Track a bulk delete event
   *
   * @remarks **Plan availability:** Free, Pro, Enterprise
   */
  async trackBulkDelete(
    actorId: string,
    recordCount: number,
    options: Omit<TrackOptions, "actor"> = {}
  ): Promise<void> {
    return this.track("data.bulk_delete", {
      actor: actorId,
      metadata: {
        records_deleted: recordCount,
        ...options.metadata,
      },
      ...options,
    });
  }

  /**
   * Track a role change event
   *
   * @remarks **Plan availability:** Free, Pro, Enterprise
   */
  async trackRoleChanged(
    actorId: string,
    oldRole: string,
    newRole: string,
    options: Omit<TrackOptions, "actor"> = {}
  ): Promise<void> {
    return this.track("authz.role_changed", {
      actor: actorId,
      metadata: {
        old_role: oldRole,
        new_role: newRole,
        ...options.metadata,
      },
      ...options,
    });
  }

  /**
   * Track an access denied event
   *
   * @remarks **Plan availability:** Free, Pro, Enterprise
   */
  async trackAccessDenied(
    actorId: string,
    resource: string,
    options: Omit<TrackOptions, "actor"> = {}
  ): Promise<void> {
    return this.track("authz.access_denied", {
      actor: actorId,
      metadata: {
        resource,
        ...options.metadata,
      },
      ...options,
    });
  }

  // ============================================
  // PRIVATE METHODS
  // ============================================

  /**
   * Schedule a flush after the flush interval
   */
  private scheduleFlush(): void {
    if (this.flushTimer) return;

    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      this.flush().catch((error) => this.handleError("scheduled flush", error));
    }, this.flushInterval);
  }

  /**
   * Make a request to the Management API
   * Handles authentication, errors, and response parsing
   */
  private async makeRequest<T>(
    method: "GET" | "POST" | "PATCH" | "DELETE",
    url: string,
    body?: Record<string, unknown>
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "X-API-Key": this.apiKey,
        "User-Agent": USER_AGENT,
      };

      const requestInit: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };

      if (body && (method === "POST" || method === "PATCH")) {
        requestInit.body = JSON.stringify(body);
      }

      this.log(`${method} ${url}`);
      const response = await this.fetchFn(url, requestInit);
      clearTimeout(timeoutId);

      // Handle error responses
      if (!response.ok) {
        await this.handleApiError(response);
      }

      const data = await response.json();
      return data as T;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof LiteSOCError) {
        throw error;
      }

      if (error instanceof Error && error.name === "AbortError") {
        throw new LiteSOCError(`Request timed out after ${this.timeout}ms`, 408, "TIMEOUT");
      }

      throw new LiteSOCError(
        error instanceof Error ? error.message : "Unknown error",
        undefined,
        "UNKNOWN"
      );
    }
  }

  /**
   * Handle API error responses and throw appropriate errors
   */
  private async handleApiError(response: Response): Promise<never> {
    let errorBody: { error?: { code?: string; message?: string } } = {};

    try {
      errorBody = await response.json();
    } catch {
      // Response body is not JSON
    }

    const errorCode = errorBody?.error?.code;
    const errorMessage = errorBody?.error?.message;

    switch (response.status) {
      case 401:
        throw new AuthenticationError(
          errorMessage || "Invalid API key. Please check your credentials."
        );

      case 403:
        if (errorCode === "PLAN_RESTRICTED") {
          throw new PlanRestrictedError(
            errorMessage ||
              "This feature requires a Pro or Enterprise plan. Upgrade at https://www.litesoc.io/pricing"
          );
        }
        throw new LiteSOCError(errorMessage || "Access forbidden", 403, errorCode || "FORBIDDEN");

      case 404:
        throw new NotFoundError(errorMessage || "Resource not found");

      case 429: {
        const retryAfter = parseInt(response.headers.get("Retry-After") || "60", 10);
        throw new RateLimitError(
          errorMessage || `Rate limit exceeded. Please wait ${retryAfter} seconds before retrying.`,
          retryAfter
        );
      }

      case 400:
        throw new ValidationError(errorMessage || "Invalid request");

      default:
        throw new LiteSOCError(
          errorMessage || `API error: ${response.status} ${response.statusText}`,
          response.status,
          errorCode
        );
    }
  }

  /**
   * Send events to the LiteSOC ingestion API
   */
  private async sendEvents(events: QueuedEvent[]): Promise<void> {
    /* istanbul ignore if -- defensive check, flush() already filters empty */
    if (events.length === 0) return;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const isBatch = events.length > 1;
      const body = isBatch ? { events } : events[0];
      const url = `${this.baseUrl}/collect`;

      const response = await this.fetchFn(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": this.apiKey,
          "User-Agent": USER_AGENT,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`API error ${response.status}: ${errorText}`);
      }

      const result: IngestApiResponse = await response.json();

      if (result.success) {
        this.log(
          `Successfully sent ${events.length} event(s)`,
          isBatch ? `(batch, ${result.events_accepted} accepted)` : ""
        );
      } else {
        throw new Error(result.error || "Unknown API error");
      }
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === "AbortError") {
        this.log(`Request timed out after ${this.timeout}ms`);
      }

      // Re-queue events on failure (with limit to prevent infinite loop)
      const retryableEvents = events.filter(
        (e) => !((e.metadata as Record<string, number>)._retry_count > 2)
      );

      if (retryableEvents.length > 0 && this.batching) {
        this.log(`Re-queuing ${retryableEvents.length} events for retry`);
        for (const event of retryableEvents) {
          (event.metadata as Record<string, number>)._retry_count =
            ((event.metadata as Record<string, number>)._retry_count || 0) + 1;
          this.queue.unshift(event);
        }
        this.scheduleFlush();
      }

      throw error;
    }
  }

  /**
   * Handle errors based on silent mode
   */
  private handleError(context: string, error: unknown): void {
    const message = error instanceof Error ? error.message : "Unknown error";

    if (this.silent) {
      this.log(`Error in ${context}: ${message}`);
    } else {
      throw error;
    }
  }

  /**
   * Log debug messages
   */
  private log(...args: unknown[]): void {
    if (this.debug) {
      console.log("[LiteSOC]", ...args);
    }
  }
}

// ============================================
// FACTORY FUNCTION
// ============================================

/**
 * Create a new LiteSOC SDK instance
 *
 * @param options - SDK configuration options
 * @returns LiteSOC SDK instance
 *
 * @example
 * ```typescript
 * import { createLiteSOC } from 'litesoc';
 *
 * const litesoc = createLiteSOC({ apiKey: 'your-api-key' });
 * ```
 */
export function createLiteSOC(options: LiteSOCOptions): LiteSOC {
  return new LiteSOC(options);
}

// ============================================
// DEFAULT EXPORT
// ============================================

export default LiteSOC;
