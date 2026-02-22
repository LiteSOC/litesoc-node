/**
 * LiteSOC Node.js/TypeScript SDK
 * Official SDK for security event tracking and threat detection
 *
 * @packageDocumentation
 */

// ============================================
// TYPE DEFINITIONS
// ============================================

/** Fetch function type for cross-environment compatibility */
type FetchFunction = (
  input: string | URL | Request,
  init?: RequestInit
) => Promise<Response>;

/**
 * Authentication events
 */
export type AuthEvent =
  | "auth.login_success"
  | "auth.login_failed"
  | "auth.logout"
  | "auth.password_changed"
  | "auth.password_reset_requested"
  | "auth.password_reset_completed"
  | "auth.mfa_enabled"
  | "auth.mfa_disabled"
  | "auth.mfa_challenge_success"
  | "auth.mfa_challenge_failed"
  | "auth.session_created"
  | "auth.session_revoked"
  | "auth.token_refreshed"
  | "auth.failed"; // Legacy alias

/**
 * User events
 */
export type UserEvent =
  | "user.created"
  | "user.updated"
  | "user.deleted"
  | "user.email_changed"
  | "user.email_verified"
  | "user.phone_changed"
  | "user.phone_verified"
  | "user.profile_updated"
  | "user.avatar_changed"
  | "user.login_failed" // Alternative format
  | "user.login.failed"; // Dot format

/**
 * Authorization events
 */
export type AuthzEvent =
  | "authz.role_assigned"
  | "authz.role_removed"
  | "authz.role_changed"
  | "authz.permission_granted"
  | "authz.permission_revoked"
  | "authz.access_denied"
  | "authz.access_granted";

/**
 * Admin events
 */
export type AdminEvent =
  | "admin.privilege_escalation"
  | "admin.user_impersonation"
  | "admin.settings_changed"
  | "admin.api_key_created"
  | "admin.api_key_revoked"
  | "admin.invite_sent"
  | "admin.invite_accepted"
  | "admin.member_removed";

/**
 * Data events
 */
export type DataEvent =
  | "data.export"
  | "data.import"
  | "data.bulk_delete"
  | "data.bulk_update"
  | "data.sensitive_access"
  | "data.download"
  | "data.upload"
  | "data.shared"
  | "data.unshared";

/**
 * Security events
 */
export type SecurityEvent =
  | "security.suspicious_activity"
  | "security.rate_limit_exceeded"
  | "security.ip_blocked"
  | "security.ip_unblocked"
  | "security.account_locked"
  | "security.account_unlocked"
  | "security.brute_force_detected"
  | "security.impossible_travel"
  | "security.geo_anomaly";

/**
 * API events
 */
export type ApiEvent =
  | "api.key_used"
  | "api.rate_limited"
  | "api.error"
  | "api.webhook_sent"
  | "api.webhook_failed";

/**
 * Billing events
 */
export type BillingEvent =
  | "billing.subscription_created"
  | "billing.subscription_updated"
  | "billing.subscription_cancelled"
  | "billing.payment_succeeded"
  | "billing.payment_failed"
  | "billing.invoice_created"
  | "billing.invoice_paid";

/**
 * All predefined event types
 */
export type PredefinedEventType =
  | AuthEvent
  | UserEvent
  | AuthzEvent
  | AdminEvent
  | DataEvent
  | SecurityEvent
  | ApiEvent
  | BillingEvent;

/**
 * Custom event type (string pattern: category.action)
 */
export type CustomEventType = `${string}.${string}`;

/**
 * All supported event types
 */
export type EventType = PredefinedEventType | CustomEventType;

/**
 * Event severity levels
 */
export type EventSeverity = "low" | "medium" | "high" | "critical";

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
  /** Event severity (optional, auto-detected for known events) */
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
 * API response structure
 */
interface ApiResponse {
  success: boolean;
  event_id?: string;
  events_accepted?: number;
  error?: string;
}

/**
 * SDK configuration options
 */
export interface LiteSOCOptions {
  /** Your LiteSOC API key */
  apiKey: string;
  /** API endpoint (defaults to https://www.litesoc.io/api/v1/collect) */
  endpoint?: string;
  /** Enable batching (defaults to true) */
  batching?: boolean;
  /** Batch size before auto-flush (defaults to 10) */
  batchSize?: number;
  /** Batch flush interval in milliseconds (defaults to 5000ms) */
  flushInterval?: number;
  /** Enable debug logging (defaults to false) */
  debug?: boolean;
  /** Fail silently on errors (defaults to true) */
  silent?: boolean;
  /** Custom fetch implementation (for Edge runtimes) */
  fetch?: FetchFunction;
}

// ============================================
// LITESOC SDK CLASS
// ============================================

/**
 * LiteSOC SDK for tracking security events
 *
 * @example
 * ```typescript
 * import { LiteSOC } from 'litesoc';
 *
 * const litesoc = new LiteSOC({ apiKey: 'your-api-key' });
 *
 * // Track a login failure
 * await litesoc.track('auth.login_failed', {
 *   actor: { id: 'user_123', email: 'user@example.com' },
 *   userIp: '192.168.1.1',
 *   metadata: { reason: 'invalid_password' }
 * });
 *
 * // Flush remaining events before shutdown
 * await litesoc.flush();
 * ```
 */
export class LiteSOC {
  private readonly apiKey: string;
  private readonly endpoint: string;
  private readonly batching: boolean;
  private readonly batchSize: number;
  private readonly flushInterval: number;
  private readonly debug: boolean;
  private readonly silent: boolean;
  private readonly fetchFn: FetchFunction;

  private queue: QueuedEvent[] = [];
  private flushTimer: ReturnType<typeof globalThis.setTimeout> | null = null;
  private isFlushing = false;

  /**
   * Create a new LiteSOC SDK instance
   *
   * @param options - SDK configuration options
   * @throws Error if apiKey is not provided
   */
  constructor(options: LiteSOCOptions) {
    if (!options.apiKey) {
      throw new Error("LiteSOC: apiKey is required");
    }

    this.apiKey = options.apiKey;
    this.endpoint =
      options.endpoint || "https://www.litesoc.io/api/v1/collect";
    this.batching = options.batching ?? true;
    this.batchSize = options.batchSize ?? 10;
    this.flushInterval = options.flushInterval ?? 5000;
    this.debug = options.debug ?? false;
    this.silent = options.silent ?? true;
    this.fetchFn = options.fetch ?? fetch;

    // Validate fetch is available
    if (!this.fetchFn) {
      throw new Error(
        "LiteSOC: fetch is not available. Please provide a custom fetch implementation."
      );
    }

    this.log("Initialized with endpoint:", this.endpoint);
  }

  /**
   * Track a security event
   *
   * @param eventName - The event type (e.g., 'auth.login_failed')
   * @param options - Event options including actor, IP, and metadata
   * @returns Promise that resolves when the event is queued or sent
   *
   * @example
   * ```typescript
   * // Track with full options
   * await litesoc.track('auth.login_failed', {
   *   actor: { id: 'user_123', email: 'user@example.com' },
   *   userIp: '192.168.1.1',
   *   metadata: { reason: 'invalid_password', attempts: 3 }
   * });
   *
   * // Track with shorthand actor
   * await litesoc.track('user.created', {
   *   actor: 'user_456',
   *   actorEmail: 'newuser@example.com'
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
        // If only email is provided, use it as both id and email
        actor = { id: options.actorEmail, email: options.actorEmail };
      }

      // Build the event
      const event: QueuedEvent = {
        event: eventName,
        actor,
        user_ip: options.userIp || null,
        metadata: {
          ...options.metadata,
          // Auto-enrich with SDK info
          _sdk: "litesoc-node",
          _sdk_version: "1.0.0",
          // Include severity if provided
          ...(options.severity ? { _severity: options.severity } : {}),
        },
        timestamp:
          options.timestamp instanceof Date
            ? options.timestamp.toISOString()
            : options.timestamp || new Date().toISOString(),
      };

      this.log("Tracking event:", eventName, event);

      if (this.batching) {
        // Add to queue
        this.queue.push(event);
        this.log(`Event queued. Queue size: ${this.queue.length}`);

        // Auto-flush if batch size reached
        if (this.queue.length >= this.batchSize) {
          await this.flush();
        } else {
          // Schedule flush if not already scheduled
          this.scheduleFlush();
        }
      } else {
        // Send immediately
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
   * @example
   * ```typescript
   * // Flush before application shutdown
   * process.on('beforeExit', async () => {
   *   await litesoc.flush();
   * });
   * ```
   */
  async flush(): Promise<void> {
    // Prevent concurrent flushes
    if (this.isFlushing) {
      this.log("Flush already in progress, skipping");
      return;
    }

    // Clear scheduled flush
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    // Get events to send
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
    await this.flush();
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    this.log("Shutdown complete");
  }

  // ============================================
  // CONVENIENCE METHODS
  // ============================================

  /**
   * Track a login failure event
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
   */
  async trackSensitiveAccess(
    actorId: string,
    resource: string,
    options: Omit<TrackOptions, "actor"> = {}
  ): Promise<void> {
    return this.track("data.sensitive_access", {
      actor: actorId,
      severity: "high",
      metadata: {
        resource,
        ...options.metadata,
      },
      ...options,
    });
  }

  /**
   * Track a bulk delete event
   */
  async trackBulkDelete(
    actorId: string,
    recordCount: number,
    options: Omit<TrackOptions, "actor"> = {}
  ): Promise<void> {
    return this.track("data.bulk_delete", {
      actor: actorId,
      severity: "high",
      metadata: {
        records_deleted: recordCount,
        ...options.metadata,
      },
      ...options,
    });
  }

  /**
   * Track a role change event
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
   * Send events to the LiteSOC API
   */
  private async sendEvents(events: QueuedEvent[]): Promise<void> {
    if (events.length === 0) return;

    try {
      // If single event, send directly; otherwise send as batch
      const isBatch = events.length > 1;
      const body = isBatch ? { events } : events[0];

      const response = await this.fetchFn(this.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
          "User-Agent": "litesoc-node/1.0.0",
        },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`API error ${response.status}: ${errorText}`);
      }

      const result: ApiResponse = await response.json();

      if (result.success) {
        this.log(
          `Successfully sent ${events.length} event(s)`,
          isBatch ? `(batch, ${result.events_accepted} accepted)` : ""
        );
      } else {
        throw new Error(result.error || "Unknown API error");
      }
    } catch (error) {
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
    const message =
      error instanceof Error ? error.message : "Unknown error";

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
