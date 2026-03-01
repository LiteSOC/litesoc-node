import {
  LiteSOC,
  createLiteSOC,
  SDK_VERSION,
  USER_AGENT,
  DEFAULT_BASE_URL,
  AuthenticationError,
  PlanRestrictedError,
  RateLimitError,
  NotFoundError,
  ValidationError,
  LiteSOCError,
} from "./index";

/**
 * Helper to create a mock response with plan headers
 */
function createMockResponse(
  data: unknown,
  options: {
    ok?: boolean;
    status?: number;
    plan?: "free" | "pro" | "enterprise";
    retentionDays?: number;
    cutoffDate?: string;
    headers?: Record<string, string>;
  } = {}
): {
  ok: boolean;
  status: number;
  headers: { get: (name: string) => string | null };
  json: () => Promise<unknown>;
  text: () => Promise<string>;
} {
  const {
    ok = true,
    status = 200,
    plan = "pro",
    retentionDays = 30,
    cutoffDate = "2026-02-01T00:00:00Z",
    headers = {},
  } = options;

  const allHeaders: Record<string, string> = {
    "X-LiteSOC-Plan": plan,
    "X-LiteSOC-Retention": String(retentionDays),
    "X-LiteSOC-Cutoff": cutoffDate,
    ...headers,
  };

  return {
    ok,
    status,
    headers: {
      get: (name: string) => allHeaders[name] || null,
    },
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

describe("LiteSOC SDK", () => {
  let mockFetch: jest.Mock;
  const originalFetch = global.fetch;

  beforeEach(() => {
    jest.useFakeTimers();
    mockFetch = jest.fn().mockResolvedValue(
      createMockResponse({ success: true })
    );
    global.fetch = mockFetch;
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
    global.fetch = originalFetch;
  });

  describe("Constants", () => {
    it("should export SDK_VERSION", () => {
      expect(SDK_VERSION).toBe("2.1.0");
    });

    it("should export USER_AGENT", () => {
      expect(USER_AGENT).toBe("litesoc-node-sdk/2.1.0");
    });

    it("should export DEFAULT_BASE_URL", () => {
      expect(DEFAULT_BASE_URL).toBe("https://api.litesoc.io");
    });
  });

  describe("Error Classes", () => {
    it("should create RateLimitError with retryAfter", () => {
      const error = new RateLimitError("Rate limited", 60);
      expect(error.message).toBe("Rate limited");
      expect(error.retryAfter).toBe(60);
      expect(error.statusCode).toBe(429);
      expect(error.code).toBe("RATE_LIMIT_EXCEEDED");
      expect(error.name).toBe("RateLimitError");
    });

    it("should create NotFoundError", () => {
      const error = new NotFoundError("Not found");
      expect(error.message).toBe("Not found");
      expect(error.statusCode).toBe(404);
      expect(error.code).toBe("NOT_FOUND");
      expect(error.name).toBe("NotFoundError");
    });

    it("should create ValidationError", () => {
      const error = new ValidationError("Invalid input");
      expect(error.message).toBe("Invalid input");
      expect(error.statusCode).toBe(400);
      expect(error.code).toBe("VALIDATION_ERROR");
      expect(error.name).toBe("ValidationError");
    });

    it("should create AuthenticationError with default message", () => {
      const error = new AuthenticationError();
      expect(error.message).toBe("Invalid API key. Please check your credentials.");
      expect(error.statusCode).toBe(401);
    });

    it("should create PlanRestrictedError with default message", () => {
      const error = new PlanRestrictedError();
      expect(error.message).toContain("Pro or Enterprise plan");
      expect(error.statusCode).toBe(403);
    });

    it("should create RateLimitError with default message", () => {
      const error = new RateLimitError();
      expect(error.message).toContain("Rate limit exceeded");
      expect(error.retryAfter).toBeUndefined();
    });

    it("should create NotFoundError with default message", () => {
      const error = new NotFoundError();
      expect(error.message).toBe("Resource not found");
    });
  });

  describe("Constructor", () => {
    it("should require an API key", () => {
      expect(() => new LiteSOC({ apiKey: "" })).toThrow("LiteSOC: apiKey is required");
    });

    it("should accept a valid API key", () => {
      const client = new LiteSOC({ apiKey: "test-api-key" });
      expect(client).toBeInstanceOf(LiteSOC);
    });

    it("should use default base URL if not provided", () => {
      const client = new LiteSOC({ apiKey: "test-api-key" });
      expect(client["baseUrl"]).toBe("https://api.litesoc.io");
    });

    it("should use custom base URL", () => {
      const client = new LiteSOC({ apiKey: "test-api-key", baseUrl: "https://custom.api.com" });
      expect(client["baseUrl"]).toBe("https://custom.api.com");
    });

    it("should set default batch size", () => {
      const client = new LiteSOC({ apiKey: "test-api-key" });
      expect(client["batchSize"]).toBe(10);
    });

    it("should set custom batch size", () => {
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 5 });
      expect(client["batchSize"]).toBe(5);
    });

    it("should set default flush interval", () => {
      const client = new LiteSOC({ apiKey: "test-api-key" });
      expect(client["flushInterval"]).toBe(5000);
    });

    it("should set custom flush interval", () => {
      const client = new LiteSOC({ apiKey: "test-api-key", flushInterval: 10000 });
      expect(client["flushInterval"]).toBe(10000);
    });

    it("should set debug mode", () => {
      const consoleSpy = jest.spyOn(console, "log").mockImplementation();
      const client = new LiteSOC({ apiKey: "test-api-key", debug: true });
      expect(client["debug"]).toBe(true);
      expect(consoleSpy).toHaveBeenCalledWith("[LiteSOC]", "Initialized with baseUrl:", "https://api.litesoc.io");
      consoleSpy.mockRestore();
    });

    it("should set silent mode", () => {
      const client = new LiteSOC({ apiKey: "test-api-key", silent: false });
      expect(client["silent"]).toBe(false);
    });

    it("should set custom timeout", () => {
      const client = new LiteSOC({ apiKey: "test-api-key", timeout: 30000 });
      expect(client["timeout"]).toBe(30000);
    });

    it("should accept custom fetch implementation", () => {
      const customFetch = jest.fn();
      const client = new LiteSOC({ apiKey: "test-api-key", fetch: customFetch });
      expect(client["fetchFn"]).toBe(customFetch);
    });

    it("should set batching to false", () => {
      const client = new LiteSOC({ apiKey: "test-api-key", batching: false });
      expect(client["batching"]).toBe(false);
    });

    it("should throw if fetch is not available", () => {
      const originalFetch = global.fetch;
      // @ts-expect-error - Testing undefined fetch
      global.fetch = undefined;
      expect(() => new LiteSOC({ apiKey: "test-api-key" })).toThrow("fetch is not available");
      global.fetch = originalFetch;
    });
  });

  describe("track()", () => {
    it("should queue events and flush when batch size is reached", async () => {
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 2 });

      await client.track("auth.login_success", { actor: { id: "user-1" } });
      expect(mockFetch).not.toHaveBeenCalled();

      await client.track("auth.login_success", { actor: { id: "user-2" } });
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should send correct payload to /collect endpoint", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true, events_accepted: 2 }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 2 });

      await client.track("auth.login_success", {
        actor: { id: "user-1", email: "test@example.com" },
        userIp: "192.168.1.1",
      });
      await client.track("auth.logout", { actor: { id: "user-1" } });

      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.litesoc.io/collect",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "Content-Type": "application/json",
            "X-API-Key": "test-api-key",
            "User-Agent": "litesoc-node-sdk/2.1.0",
          }),
        })
      );

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.events).toHaveLength(2);
      expect(body.events[0]).toMatchObject({
        event: "auth.login_success",
        actor: { id: "user-1", email: "test@example.com" },
        user_ip: "192.168.1.1",
      });
    });

    it("should send single event without wrapper when batchSize is 1", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.track("auth.login_success", {
        actor: { id: "user-1", email: "test@example.com" },
        userIp: "192.168.1.1",
      });

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event).toBe("auth.login_success");
      expect(body.actor).toEqual({ id: "user-1", email: "test@example.com" });
      expect(body.user_ip).toBe("192.168.1.1");
    });

    it("should send immediately when batching is disabled", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batching: false });

      await client.track("auth.login_success", { actor: { id: "user-1" } });
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should use string actor shorthand", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.track("auth.login_success", {
        actor: "user-123",
        actorEmail: "user@example.com",
      });

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.actor).toEqual({ id: "user-123", email: "user@example.com" });
    });

    it("should create actor from actorEmail when no actor provided", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.track("auth.login_success", {
        actorEmail: "user@example.com",
      });

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.actor).toEqual({ id: "user@example.com", email: "user@example.com" });
    });

    it("should use Date timestamp", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });
      const timestamp = new Date("2024-01-01T00:00:00Z");

      await client.track("auth.login_success", {
        actor: { id: "user-1" },
        timestamp,
      });

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.timestamp).toBe("2024-01-01T00:00:00.000Z");
    });

    it("should use string timestamp", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.track("auth.login_success", {
        actor: { id: "user-1" },
        timestamp: "2024-01-01T00:00:00Z",
      });

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.timestamp).toBe("2024-01-01T00:00:00Z");
    });

    it("should strip severity from payload (server-side assignment)", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      // Pass severity in options - should be stripped
      await client.track("auth.login_failed", {
        actor: { id: "user-1" },
        severity: "critical",  // This should be ignored
      });

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      // Severity should NOT be in metadata (server assigns it)
      expect(body.metadata._severity).toBeUndefined();
      expect(body.metadata._sdk).toBe("litesoc-node");
    });

    it("should handle errors silently in silent mode", async () => {
      mockFetch.mockRejectedValue(new Error("Network error"));

      const consoleSpy = jest.spyOn(console, "log").mockImplementation();
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, debug: true, silent: true });

      await client.track("auth.login_success", { actor: { id: "user-1" } });

      expect(consoleSpy).toHaveBeenCalledWith("[LiteSOC]", expect.stringContaining("Error in track"));
      consoleSpy.mockRestore();
    });

    it("should throw errors when silent mode is disabled", async () => {
      mockFetch.mockRejectedValue(new Error("Network error"));

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, silent: false });

      await expect(client.track("auth.login_success", { actor: { id: "user-1" } })).rejects.toThrow("Network error");
    });

    it("should schedule flush after adding event below batch size", async () => {
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 10, flushInterval: 5000 });

      await client.track("auth.login_success", { actor: { id: "user-1" } });
      expect(mockFetch).not.toHaveBeenCalled();

      // Fast-forward timer to trigger the scheduleFlush callback
      await jest.advanceTimersByTimeAsync(5000);

      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should handle scheduled flush error silently", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Scheduled flush error"));

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 10, flushInterval: 5000, debug: true, silent: true });
      const consoleSpy = jest.spyOn(console, "log").mockImplementation();

      await client.track("auth.login_success", { actor: { id: "user-1" } });

      // Fast-forward timer to trigger the scheduleFlush callback with error
      await jest.advanceTimersByTimeAsync(5000);

      expect(consoleSpy).toHaveBeenCalledWith("[LiteSOC]", expect.stringContaining("Error"));
      consoleSpy.mockRestore();
    });
  });

  describe("flush()", () => {
    it("should send all queued events", async () => {
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 100 });

      await client.track("auth.login_success", { actor: { id: "1" } });
      await client.track("auth.logout", { actor: { id: "2" } });

      expect(mockFetch).not.toHaveBeenCalled();
      await client.flush();
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should not send if queue is empty", async () => {
      const client = new LiteSOC({ apiKey: "test-api-key" });
      await client.flush();
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("should not send if already flushing", async () => {
      let resolveFirst: () => void;
      const firstPromise = new Promise<void>((resolve) => {
        resolveFirst = resolve;
      });

      mockFetch.mockImplementationOnce(async () => {
        await firstPromise;
        return { ok: true, status: 200, json: async () => ({ success: true }) };
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 100 });
      await client.track("auth.login_success", { actor: { id: "1" } });

      const flush1 = client.flush();
      const flush2 = client.flush();

      resolveFirst!();
      await Promise.all([flush1, flush2]);

      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should silently handle failure and re-queue events", async () => {
      // First call fails, triggers re-queue
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      // Track returns void and handles errors silently
      await client.track("auth.login_success", { actor: { id: "1" } });

      // Event should be re-queued after failure
      expect(client.getQueueSize()).toBe(1);
    });
  });

  describe("Management API", () => {
    describe("getAlerts()", () => {
      it("should fetch alerts with default params and metadata", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse(
            { data: [], total: 0, limit: 100, offset: 0 },
            { plan: "pro", retentionDays: 30 }
          )
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getAlerts();

        expect(mockFetch).toHaveBeenCalledWith(
          "https://api.litesoc.io/alerts",
          expect.objectContaining({ method: "GET" })
        );
        expect(result.data).toEqual({ data: [], total: 0, limit: 100, offset: 0 });
        expect(result.metadata.plan).toBe("pro");
        expect(result.metadata.retentionDays).toBe(30);
      });

      it("should fetch alerts with filters", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse({ data: [], total: 0, limit: 10, offset: 0 })
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        await client.getAlerts({ status: "open", severity: "critical", alertType: "brute_force_attack", limit: 10, offset: 5 });

        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining("status=open"),
          expect.any(Object)
        );
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining("severity=critical"),
          expect.any(Object)
        );
      });

      it("should throw PlanRestrictedError on 403 with PLAN_RESTRICTED code", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          json: async () => ({ error: { code: "PLAN_RESTRICTED", message: "Plan upgrade required" } }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        await expect(client.getAlerts()).rejects.toThrow(PlanRestrictedError);
      });

      it("should throw LiteSOCError on 403 without PLAN_RESTRICTED code", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          json: async () => ({ error: { message: "Access forbidden" } }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        await expect(client.getAlerts()).rejects.toThrow(LiteSOCError);
      });
    });

    describe("getAlert()", () => {
      it("should fetch single alert with metadata", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse(
            { data: { id: "alert-123", status: "open" } },
            { plan: "pro", retentionDays: 30 }
          )
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getAlert("alert-123");

        expect(mockFetch).toHaveBeenCalledWith(
          "https://api.litesoc.io/alerts/alert-123",
          expect.objectContaining({ method: "GET" })
        );
        expect(result.data.id).toBe("alert-123");
        expect(result.metadata.plan).toBe("pro");
        expect(result.metadata.retentionDays).toBe(30);
      });

      it("should throw ValidationError when alertId is empty", async () => {
        const client = new LiteSOC({ apiKey: "test-api-key" });
        await expect(client.getAlert("")).rejects.toThrow(ValidationError);
      });

      it("should handle alert with trigger_event_id and forensics", async () => {
        const alertWithForensics = {
          id: "alert-456",
          alert_type: "brute_force_attack",
          severity: "high",
          status: "open",
          title: "Brute Force Attack Detected",
          description: "Multiple failed login attempts",
          source_ip: "192.168.1.100",
          actor_id: "user_123",
          trigger_event_id: "evt_abc123",
          forensics: {
            network: {
              is_vpn: true,
              is_tor: false,
              is_proxy: false,
              is_datacenter: true,
              is_mobile: false,
              asn: 12345,
              asn_org: "Example Hosting Inc",
              isp: "Example ISP",
            },
            location: {
              city: "New York",
              region: "New York",
              country_code: "US",
              country_name: "United States",
              latitude: 40.7128,
              longitude: -74.006,
              timezone: "America/New_York",
            },
          },
          created_at: "2026-03-01T12:00:00Z",
          updated_at: "2026-03-01T12:00:00Z",
          resolved_at: null,
          resolution_notes: null,
          metadata: {},
        };

        mockFetch.mockResolvedValueOnce(
          createMockResponse({ data: alertWithForensics }, { plan: "enterprise" })
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getAlert("alert-456");

        expect(result.data.trigger_event_id).toBe("evt_abc123");
        expect(result.data.forensics).toBeDefined();
        expect(result.data.forensics!.network.is_vpn).toBe(true);
        expect(result.data.forensics!.network.asn).toBe(12345);
        expect(result.data.forensics!.location.city).toBe("New York");
        expect(result.data.forensics!.location.country_code).toBe("US");
      });

      it("should handle alert with null forensics (Free tier)", async () => {
        const alertWithoutForensics = {
          id: "alert-789",
          alert_type: "geo_anomaly",
          severity: "medium",
          status: "open",
          title: "Geographic Anomaly",
          description: null,
          source_ip: "10.0.0.1",
          actor_id: "user_456",
          trigger_event_id: "evt_xyz789",
          forensics: null,
          created_at: "2026-03-01T12:00:00Z",
          updated_at: "2026-03-01T12:00:00Z",
          resolved_at: null,
          resolution_notes: null,
          metadata: {},
        };

        mockFetch.mockResolvedValueOnce(
          createMockResponse({ data: alertWithoutForensics }, { plan: "free" })
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getAlert("alert-789");

        expect(result.data.trigger_event_id).toBe("evt_xyz789");
        expect(result.data.forensics).toBeNull();
        // Accessing forensics properties should not throw when null
        expect(result.data.forensics?.network?.is_vpn).toBeUndefined();
      });

      it("should handle alert with null trigger_event_id", async () => {
        const alertWithNullTrigger = {
          id: "alert-999",
          alert_type: "suspicious_activity",
          severity: "low",
          status: "open",
          title: "Suspicious Activity",
          description: null,
          source_ip: null,
          actor_id: null,
          trigger_event_id: null,
          forensics: null,
          created_at: "2026-03-01T12:00:00Z",
          updated_at: "2026-03-01T12:00:00Z",
          resolved_at: null,
          resolution_notes: null,
          metadata: {},
        };

        mockFetch.mockResolvedValueOnce(
          createMockResponse({ data: alertWithNullTrigger }, { plan: "free" })
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getAlert("alert-999");

        expect(result.data.trigger_event_id).toBeNull();
        expect(result.data.forensics).toBeNull();
      });
    });

    describe("resolveAlert()", () => {
      it("should PATCH to alert endpoint with resolution type and notes", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse(
            { data: { id: "alert-123", status: "resolved" } },
            { plan: "enterprise" }
          )
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.resolveAlert("alert-123", "false_positive", "False positive - verified");

        expect(mockFetch).toHaveBeenCalledWith(
          "https://api.litesoc.io/alerts/alert-123",
          expect.objectContaining({ method: "PATCH" })
        );
        const body = JSON.parse(mockFetch.mock.calls[0][1].body);
        expect(body.action).toBe("resolve");
        expect(body.resolution_type).toBe("false_positive");
        expect(body.internal_notes).toBe("False positive - verified");
        expect(result.data.status).toBe("resolved");
        expect(result.metadata.plan).toBe("enterprise");
      });

      it("should resolve with default resolution type and no notes", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse({ data: { id: "alert-123", status: "resolved" } })
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        await client.resolveAlert("alert-123");

        const body = JSON.parse(mockFetch.mock.calls[0][1].body);
        expect(body.action).toBe("resolve");
        expect(body.resolution_type).toBe("other");
        expect(body.internal_notes).toBeUndefined();
      });

      it("should throw ValidationError when alertId is empty", async () => {
        const client = new LiteSOC({ apiKey: "test-api-key" });
        await expect(client.resolveAlert("")).rejects.toThrow(ValidationError);
      });
    });

    describe("markAlertSafe()", () => {
      it("should PATCH to alert endpoint with action mark_safe and notes", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse(
            { data: { id: "alert-123", status: "dismissed" } },
            { plan: "pro" }
          )
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.markAlertSafe("alert-123", "Known behavior");

        expect(mockFetch).toHaveBeenCalledWith(
          "https://api.litesoc.io/alerts/alert-123",
          expect.objectContaining({ method: "PATCH" })
        );
        const body = JSON.parse(mockFetch.mock.calls[0][1].body);
        expect(body.action).toBe("mark_safe");
        expect(body.internal_notes).toBe("Known behavior");
        expect(result.data.status).toBe("dismissed");
        expect(result.metadata.plan).toBe("pro");
      });

      it("should mark safe without notes", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse({ data: { id: "alert-123", status: "dismissed" } })
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        await client.markAlertSafe("alert-123");

        const body = JSON.parse(mockFetch.mock.calls[0][1].body);
        expect(body.action).toBe("mark_safe");
        expect(body.internal_notes).toBeUndefined();
      });

      it("should throw ValidationError when alertId is empty", async () => {
        const client = new LiteSOC({ apiKey: "test-api-key" });
        await expect(client.markAlertSafe("")).rejects.toThrow(ValidationError);
      });
    });

    describe("getEvents()", () => {
      it("should fetch events with default params and metadata", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse(
            { data: [], total: 0, limit: 50, offset: 0 },
            { plan: "free", retentionDays: 7 }
          )
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getEvents();

        expect(mockFetch).toHaveBeenCalledWith(
          "https://api.litesoc.io/events",
          expect.objectContaining({ method: "GET" })
        );
        expect(result.data).toEqual({ data: [], total: 0, limit: 50, offset: 0 });
        expect(result.metadata.plan).toBe("free");
        expect(result.metadata.retentionDays).toBe(7);
      });

      it("should fetch events with filters", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse({ data: [], total: 0, limit: 50, offset: 0 })
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        await client.getEvents({ eventName: "auth.login_failed", actorId: "user-1", severity: "warning", limit: 10, offset: 5 });

        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining("event_name=auth.login_failed"),
          expect.any(Object)
        );
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining("actor_id=user-1"),
          expect.any(Object)
        );
      });
    });

    describe("getEvent()", () => {
      it("should fetch single event with metadata", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse(
            { data: { id: "evt-123", event_name: "auth.login_success" } },
            { plan: "enterprise", retentionDays: 90 }
          )
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getEvent("evt-123");

        expect(mockFetch).toHaveBeenCalledWith(
          "https://api.litesoc.io/events/evt-123",
          expect.objectContaining({ method: "GET" })
        );
        expect(result.data.id).toBe("evt-123");
        expect(result.metadata.plan).toBe("enterprise");
        expect(result.metadata.retentionDays).toBe(90);
      });

      it("should throw ValidationError when eventId is empty", async () => {
        const client = new LiteSOC({ apiKey: "test-api-key" });
        await expect(client.getEvent("")).rejects.toThrow(ValidationError);
      });
    });

    describe("getPlanInfo()", () => {
      it("should fetch plan info from events endpoint", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse(
            { data: [], total: 0, limit: 1, offset: 0 },
            { plan: "pro", retentionDays: 30, cutoffDate: "2026-01-30T00:00:00Z" }
          )
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getPlanInfo();

        expect(mockFetch).toHaveBeenCalledWith(
          "https://api.litesoc.io/events?limit=1",
          expect.objectContaining({ method: "GET" })
        );
        expect(result.plan).toBe("pro");
        expect(result.retentionDays).toBe(30);
        expect(result.cutoffDate).toBe("2026-01-30T00:00:00Z");
        expect(result.hasManagementApi).toBe(true);
        expect(result.hasBehavioralAi).toBe(true);
      });

      it("should return correct features for free plan", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse(
            { data: [], total: 0, limit: 1, offset: 0 },
            { plan: "free", retentionDays: 7 }
          )
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getPlanInfo();

        expect(result.plan).toBe("free");
        expect(result.retentionDays).toBe(7);
        expect(result.hasManagementApi).toBe(false);
        expect(result.hasBehavioralAi).toBe(false);
      });

      it("should return correct features for enterprise plan", async () => {
        mockFetch.mockResolvedValueOnce(
          createMockResponse(
            { data: [], total: 0, limit: 1, offset: 0 },
            { plan: "enterprise", retentionDays: 90 }
          )
        );

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getPlanInfo();

        expect(result.plan).toBe("enterprise");
        expect(result.retentionDays).toBe(90);
        expect(result.hasManagementApi).toBe(true);
        expect(result.hasBehavioralAi).toBe(true);
      });

      it("should handle missing plan headers gracefully", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: { get: () => null },
          json: async () => ({ data: [], total: 0, limit: 1, offset: 0 }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const result = await client.getPlanInfo();

        expect(result.plan).toBeNull();
        expect(result.retentionDays).toBeNull();
        expect(result.cutoffDate).toBeNull();
        expect(result.hasManagementApi).toBe(false);
        expect(result.hasBehavioralAi).toBe(false);
      });
    });
  });

  describe("Error Handling", () => {
    it("should throw AuthenticationError on 401", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        headers: { get: () => null },
        json: async () => ({ error: { message: "Invalid API key" } }),
      });

      const client = new LiteSOC({ apiKey: "invalid-key" });
      await expect(client.getAlerts()).rejects.toThrow(AuthenticationError);
    });

    it("should throw NotFoundError on 404", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        headers: { get: () => null },
        json: async () => ({ error: { message: "Alert not found" } }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key" });
      await expect(client.getAlert("nonexistent")).rejects.toThrow(NotFoundError);
    });

    it("should throw RateLimitError on 429", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: { get: (name: string) => (name === "Retry-After" ? "60" : null) },
        json: async () => ({ error: { message: "Rate limit exceeded" } }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key" });
      try {
        await client.getAlerts();
      } catch (error) {
        expect(error).toBeInstanceOf(RateLimitError);
        expect((error as RateLimitError).retryAfter).toBe(60);
      }
    });

    it("should throw ValidationError on 400", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ error: { message: "Invalid request" } }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key" });
      await expect(client.getAlerts()).rejects.toThrow(ValidationError);
    });

    it("should throw LiteSOCError for other errors", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: async () => ({}),
      });

      const client = new LiteSOC({ apiKey: "test-api-key" });
      await expect(client.getAlerts()).rejects.toThrow(LiteSOCError);
    });

    it("should handle non-JSON error responses", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: async () => { throw new Error("Not JSON"); },
      });

      const client = new LiteSOC({ apiKey: "test-api-key" });
      await expect(client.getAlerts()).rejects.toThrow(LiteSOCError);
    });

    it("should throw timeout error on abort", async () => {
      mockFetch.mockImplementationOnce(() => {
        const error = new Error("Aborted");
        error.name = "AbortError";
        throw error;
      });

      const client = new LiteSOC({ apiKey: "test-api-key", timeout: 100 });
      await expect(client.getAlerts()).rejects.toThrow("timed out");
    });

    it("should trigger timeout callback when request takes too long", async () => {
      // Make fetch hang indefinitely until signal is aborted
      mockFetch.mockImplementationOnce((_url: string, options: { signal: AbortSignal }) => {
        return new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () => {
            const error = new Error("Aborted");
            error.name = "AbortError";
            reject(error);
          });
        });
      });

      const client = new LiteSOC({ apiKey: "test-api-key", timeout: 100 });
      const promise = client.getAlerts();

      // Advance timer to trigger the abort callback
      jest.advanceTimersByTime(150);

      // Now await the promise which should have been rejected
      try {
        await promise;
        fail("Expected promise to reject");
      } catch (error) {
        expect(error).toBeInstanceOf(LiteSOCError);
        expect((error as LiteSOCError).code).toBe("TIMEOUT");
      }
    });

    it("should throw LiteSOCError for unknown errors", async () => {
      mockFetch.mockRejectedValueOnce("string error");

      const client = new LiteSOC({ apiKey: "test-api-key" });
      await expect(client.getAlerts()).rejects.toThrow(LiteSOCError);
    });
  });

  describe("Convenience Methods", () => {
    it("trackLoginFailed should track auth.login_failed", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true }) });
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.trackLoginFailed("user-1", { userIp: "192.168.1.1" });

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event).toBe("auth.login_failed");
    });

    it("trackLoginSuccess should track auth.login_success", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true }) });
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.trackLoginSuccess("user-1");

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event).toBe("auth.login_success");
    });

    it("trackPrivilegeEscalation should track admin.privilege_escalation event", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true }) });
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.trackPrivilegeEscalation("user-1");

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event).toBe("admin.privilege_escalation");
      // Severity is assigned server-side, not included in payload
      expect(body.metadata._severity).toBeUndefined();
      expect(body.metadata._sdk).toBe("litesoc-node");
    });

    it("trackSensitiveAccess should track data.sensitive_access with resource", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true }) });
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.trackSensitiveAccess("user-1", "customer_data");

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event).toBe("data.sensitive_access");
      expect(body.metadata.resource).toBe("customer_data");
    });

    it("trackBulkDelete should track data.bulk_delete with record count", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true }) });
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.trackBulkDelete("user-1", 1000);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event).toBe("data.bulk_delete");
      expect(body.metadata.records_deleted).toBe(1000);
    });

    it("trackRoleChanged should track authz.role_changed with old and new roles", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true }) });
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.trackRoleChanged("user-1", "user", "admin");

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event).toBe("authz.role_changed");
      expect(body.metadata.old_role).toBe("user");
      expect(body.metadata.new_role).toBe("admin");
    });

    it("trackAccessDenied should track authz.access_denied with resource", async () => {
      mockFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true }) });
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

      await client.trackAccessDenied("user-1", "/admin/settings");

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event).toBe("authz.access_denied");
      expect(body.metadata.resource).toBe("/admin/settings");
    });
  });

  describe("Utility Methods", () => {
    it("getQueueSize should return current queue size", async () => {
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 100 });
      expect(client.getQueueSize()).toBe(0);

      await client.track("auth.login_success", { actor: { id: "1" } });
      expect(client.getQueueSize()).toBe(1);
    });

    it("clearQueue should empty the queue", async () => {
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 100 });

      await client.track("auth.login_success", { actor: { id: "1" } });
      await client.track("auth.logout", { actor: { id: "1" } });
      expect(client.getQueueSize()).toBe(2);

      client.clearQueue();
      expect(client.getQueueSize()).toBe(0);
    });

    it("shutdown should flush remaining events", async () => {
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 100 });

      await client.track("auth.login_success", { actor: { id: "1" } });
      expect(mockFetch).not.toHaveBeenCalled();

      await client.shutdown();
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  describe("Factory Function", () => {
    it("createLiteSOC should create a LiteSOC instance", () => {
      const client = createLiteSOC({ apiKey: "test-api-key" });
      expect(client).toBeInstanceOf(LiteSOC);
    });
  });

  describe("sendEvents error handling", () => {
    it("should handle API error response in sendEvents", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: async () => "Internal Server Error",
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, silent: false });
      await expect(client.track("auth.login_success", { actor: { id: "1" } })).rejects.toThrow("API error 500");
    });

    it("should trigger sendEvents timeout callback when request hangs", async () => {
      // Make fetch hang indefinitely until signal is aborted
      mockFetch.mockImplementationOnce((_url: string, options: { signal: AbortSignal }) => {
        return new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () => {
            const error = new Error("Aborted");
            error.name = "AbortError";
            reject(error);
          });
        });
      });

      const consoleSpy = jest.spyOn(console, "log").mockImplementation();
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, timeout: 100, debug: true, silent: true });
      const promise = client.track("auth.login_success", { actor: { id: "1" } });

      // Advance timer to trigger the abort callback in sendEvents
      await jest.advanceTimersByTimeAsync(150);

      await promise; // Should resolve (silent mode)

      expect(consoleSpy).toHaveBeenCalledWith("[LiteSOC]", expect.stringContaining("timed out"));
      consoleSpy.mockRestore();
    });

    it("should handle API success false in sendEvents", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: false, error: "Invalid event format" }),
      });

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, silent: false });
      await expect(client.track("auth.login_success", { actor: { id: "1" } })).rejects.toThrow("Invalid event format");
    });

    it("should handle abort error in sendEvents", async () => {
      const abortError = new Error("Aborted");
      abortError.name = "AbortError";
      mockFetch.mockRejectedValueOnce(abortError);

      const consoleSpy = jest.spyOn(console, "log").mockImplementation();
      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, debug: true, silent: false });

      await expect(client.track("auth.login_success", { actor: { id: "1" } })).rejects.toThrow();
      expect(consoleSpy).toHaveBeenCalledWith("[LiteSOC]", expect.stringContaining("timed out"));
      consoleSpy.mockRestore();
    });

    it("should not re-queue events that have exceeded retry limit", async () => {
      mockFetch.mockRejectedValue(new Error("Network error"));

      const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, silent: false });

      // First attempt
      try { await client.track("auth.login_success", { actor: { id: "1" } }); } catch { /* ignore */ }
      expect(client.getQueueSize()).toBe(1);

      // Second attempt
      try { await client.flush(); } catch { /* ignore */ }
      expect(client.getQueueSize()).toBe(1);

      // Third attempt
      try { await client.flush(); } catch { /* ignore */ }
      expect(client.getQueueSize()).toBe(1);

      // Fourth attempt - should not re-queue
      try { await client.flush(); } catch { /* ignore */ }
      expect(client.getQueueSize()).toBe(0);
    });
  });

  describe("Additional Branch Coverage", () => {
    describe("track() actor normalization", () => {
      it("should handle track with no options parameter", async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => ({ success: true }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

        // Track without options - uses default empty object
        await client.track("auth.login_success");

        const body = JSON.parse(mockFetch.mock.calls[0][1].body);
        expect(body.event).toBe("auth.login_success");
        expect(body.actor).toBeNull();
      });

      it("should handle track with no actor and no actorEmail", async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => ({ success: true }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

        // Track with no actor at all
        await client.track("auth.login_success", {});

        const body = JSON.parse(mockFetch.mock.calls[0][1].body);
        // Actor is null when not provided (not undefined)
        expect(body.actor).toBeNull();
      });

      it("should handle actor object without email and use actorEmail", async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => ({ success: true }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });

        await client.track("auth.login_success", {
          actor: { id: "user-1" },
          actorEmail: "fallback@example.com",
        });

        const body = JSON.parse(mockFetch.mock.calls[0][1].body);
        expect(body.actor).toEqual({ id: "user-1", email: "fallback@example.com" });
      });
    });

    describe("handleApiError branches", () => {
      it("should throw AuthenticationError with default message on 401", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 401,
          statusText: "Unauthorized",
          headers: new Map(),
          json: async () => ({}),
        });

        const client = new LiteSOC({ apiKey: "bad-key" });
        await expect(client.getAlerts()).rejects.toThrow(AuthenticationError);
      });

      it("should throw PlanRestrictedError with custom message", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          statusText: "Forbidden",
          headers: new Map(),
          json: async () => ({ error: { code: "PLAN_RESTRICTED", message: "Upgrade to Pro" } }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error).toBeInstanceOf(PlanRestrictedError);
        expect(error.message).toBe("Upgrade to Pro");
      });

      it("should throw PlanRestrictedError with default message when no message provided", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          statusText: "Forbidden",
          headers: new Map(),
          json: async () => ({ error: { code: "PLAN_RESTRICTED" } }), // No message
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error).toBeInstanceOf(PlanRestrictedError);
        expect(error.message).toContain("Pro or Enterprise plan");
      });

      it("should throw LiteSOCError on 403 without PLAN_RESTRICTED code", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          statusText: "Forbidden",
          headers: new Map(),
          json: async () => ({ error: { message: "Custom forbidden" } }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error).toBeInstanceOf(LiteSOCError);
        expect(error.message).toBe("Custom forbidden");
      });

      it("should throw NotFoundError with default message on 404", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 404,
          statusText: "Not Found",
          headers: new Map(),
          json: async () => ({}),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        await expect(client.getAlert("nonexistent")).rejects.toThrow(NotFoundError);
      });

      it("should throw RateLimitError with retry-after header", async () => {
        const headers = new Map([["Retry-After", "120"]]);
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 429,
          statusText: "Too Many Requests",
          headers: { get: (key: string) => headers.get(key) },
          json: async () => ({}),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error).toBeInstanceOf(RateLimitError);
        expect(error.retryAfter).toBe(120);
      });

      it("should throw RateLimitError with default retry-after when header missing", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 429,
          statusText: "Too Many Requests",
          headers: { get: () => null }, // No Retry-After header
          json: async () => ({}),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error).toBeInstanceOf(RateLimitError);
        expect(error.retryAfter).toBe(60); // Default value
      });

      it("should throw ValidationError with default message on 400", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 400,
          statusText: "Bad Request",
          headers: new Map(),
          json: async () => ({}),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        await expect(client.getAlerts()).rejects.toThrow(ValidationError);
      });

      it("should throw LiteSOCError with status text on unknown status codes", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 500,
          statusText: "Internal Server Error",
          headers: new Map(),
          json: async () => ({}),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error).toBeInstanceOf(LiteSOCError);
        expect(error.message).toContain("500");
      });

      it("should handle JSON parse error in handleApiError", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 500,
          statusText: "Internal Server Error",
          headers: new Map(),
          json: async () => { throw new Error("Invalid JSON"); },
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        await expect(client.getAlerts()).rejects.toThrow(LiteSOCError);
      });
    });

    describe("makeRequest error handling", () => {
      it("should wrap non-Error throws in LiteSOCError", async () => {
        mockFetch.mockRejectedValueOnce("string error");

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error).toBeInstanceOf(LiteSOCError);
        expect(error.code).toBe("UNKNOWN");
      });

      it("should handle AbortError in makeRequest", async () => {
        const abortError = new Error("Aborted");
        abortError.name = "AbortError";
        mockFetch.mockRejectedValueOnce(abortError);

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error).toBeInstanceOf(LiteSOCError);
        expect(error.code).toBe("TIMEOUT");
      });

      it("should handle regular Error in makeRequest", async () => {
        mockFetch.mockRejectedValueOnce(new Error("Network failure"));

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error).toBeInstanceOf(LiteSOCError);
        expect(error.message).toBe("Network failure");
      });
    });

    describe("Convenience methods coverage", () => {
      beforeEach(() => {
        mockFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true }) });
      });

      it("trackLoginFailed should track with actor id", async () => {
        const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1 });
        await client.trackLoginFailed("user-1");

        const body = JSON.parse(mockFetch.mock.calls[0][1].body);
        expect(body.event).toBe("auth.login_failed");
        expect(body.actor.id).toBe("user-1");
      });
    });

    describe("sendEvents empty check", () => {
      it("should not send if sendEvents receives empty array", async () => {
        const client = new LiteSOC({ apiKey: "test-api-key" });

        // Force an empty flush by calling flush with empty queue
        await client.flush();

        expect(mockFetch).not.toHaveBeenCalled();
      });
    });

    describe("handleError method", () => {
      it("should throw when silent is false", async () => {
        mockFetch.mockRejectedValue(new Error("Test error"));

        const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, silent: false });

        await expect(client.track("auth.login_success", { actor: { id: "1" } })).rejects.toThrow("Test error");
      });

      it("should not throw when silent is true", async () => {
        mockFetch.mockRejectedValue(new Error("Test error"));

        const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, silent: true, debug: true });
        const consoleSpy = jest.spyOn(console, "log").mockImplementation();

        // Should not throw
        await client.track("auth.login_success", { actor: { id: "1" } });

        expect(consoleSpy).toHaveBeenCalledWith("[LiteSOC]", expect.stringContaining("Error"));
        consoleSpy.mockRestore();
      });

      it("should handle non-Error objects in handleError", async () => {
        // This triggers the "Unknown error" branch when error is not an Error instance
        mockFetch.mockRejectedValue("string error");

        const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, silent: true, debug: true });
        const consoleSpy = jest.spyOn(console, "log").mockImplementation();

        await client.track("auth.login_success", { actor: { id: "1" } });

        expect(consoleSpy).toHaveBeenCalledWith("[LiteSOC]", expect.stringContaining("Unknown error"));
        consoleSpy.mockRestore();
      });
    });

    describe("handleApiError with custom error messages", () => {
      it("should use provided error message on 403", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          statusText: "Forbidden",
          headers: new Map(),
          json: async () => ({ error: { message: "Custom forbidden message" } }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error.message).toBe("Custom forbidden message");
      });

      it("should use default message on 403 when no message provided", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          statusText: "Forbidden",
          headers: new Map(),
          json: async () => ({ error: {} }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error.message).toBe("Access forbidden");
      });

      it("should use provided error code on 403", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          statusText: "Forbidden",
          headers: new Map(),
          json: async () => ({ error: { code: "CUSTOM_CODE" } }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error.code).toBe("CUSTOM_CODE");
      });

      it("should use default code on 403 when no code provided", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 403,
          statusText: "Forbidden",
          headers: new Map(),
          json: async () => ({ error: {} }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error.code).toBe("FORBIDDEN");
      });

      it("should use provided error message on 404", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 404,
          statusText: "Not Found",
          headers: new Map(),
          json: async () => ({ error: { message: "Custom not found" } }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlert("123").catch(e => e);
        expect(error.message).toBe("Custom not found");
      });

      it("should use provided error message on 429", async () => {
        const headers = new Map([["Retry-After", "30"]]);
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 429,
          statusText: "Too Many Requests",
          headers: { get: (key: string) => headers.get(key) },
          json: async () => ({ error: { message: "Custom rate limit message" } }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error.message).toBe("Custom rate limit message");
      });

      it("should use provided error message on 400", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 400,
          statusText: "Bad Request",
          headers: new Map(),
          json: async () => ({ error: { message: "Custom validation error" } }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error.message).toBe("Custom validation error");
      });

      it("should use provided error message on 500", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 500,
          statusText: "Internal Server Error",
          headers: new Map(),
          json: async () => ({ error: { message: "Server exploded", code: "SERVER_ERROR" } }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key" });
        const error = await client.getAlerts().catch(e => e);
        expect(error.message).toBe("Server exploded");
        expect(error.code).toBe("SERVER_ERROR");
      });
    });

    describe("sendEvents result.error branch", () => {
      it("should use result.error when success is false", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ success: false, error: "Custom API error" }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, silent: false });
        await expect(client.track("auth.login_success", { actor: { id: "1" } })).rejects.toThrow("Custom API error");
      });

      it("should use default error when success is false and no error provided", async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ success: false }),
        });

        const client = new LiteSOC({ apiKey: "test-api-key", batchSize: 1, silent: false });
        await expect(client.track("auth.login_success", { actor: { id: "1" } })).rejects.toThrow("Unknown API error");
      });
    });
  });
});
