import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { LiteSOC, createLiteSOC } from "./index";

describe("LiteSOC SDK", () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ success: true, event_id: "test-123" }),
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("constructor", () => {
    it("should throw error if apiKey is not provided", () => {
      expect(() => new LiteSOC({ apiKey: "" })).toThrow(
        "LiteSOC: apiKey is required"
      );
    });

    it("should create instance with valid apiKey", () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
      });
      expect(litesoc).toBeInstanceOf(LiteSOC);
    });

    it("should use default endpoint", () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: false,
      });

      litesoc.track("auth.login_failed", { actor: "user_123" });

      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.litesoc.io/collect",
        expect.any(Object)
      );
    });

    it("should use custom endpoint", () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        endpoint: "https://custom.api.com/collect",
        fetch: mockFetch,
        batching: false,
      });

      litesoc.track("auth.login_failed", { actor: "user_123" });

      expect(mockFetch).toHaveBeenCalledWith(
        "https://custom.api.com/collect",
        expect.any(Object)
      );
    });
  });

  describe("track", () => {
    it("should track event with actor object", async () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: false,
      });

      await litesoc.track("auth.login_failed", {
        actor: { id: "user_123", email: "user@example.com" },
        userIp: "192.168.1.1",
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [, options] = mockFetch.mock.calls[0];
      const body = JSON.parse(options.body);

      expect(body.event).toBe("auth.login_failed");
      expect(body.actor.id).toBe("user_123");
      expect(body.actor.email).toBe("user@example.com");
      expect(body.user_ip).toBe("192.168.1.1");
    });

    it("should track event with actor string", async () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: false,
      });

      await litesoc.track("auth.login_failed", {
        actor: "user_123",
        actorEmail: "user@example.com",
      });

      const [, options] = mockFetch.mock.calls[0];
      const body = JSON.parse(options.body);

      expect(body.actor.id).toBe("user_123");
      expect(body.actor.email).toBe("user@example.com");
    });

    it("should include metadata", async () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: false,
      });

      await litesoc.track("auth.login_failed", {
        actor: "user_123",
        metadata: { reason: "invalid_password", attempts: 3 },
      });

      const [, options] = mockFetch.mock.calls[0];
      const body = JSON.parse(options.body);

      expect(body.metadata.reason).toBe("invalid_password");
      expect(body.metadata.attempts).toBe(3);
      expect(body.metadata._sdk).toBe("litesoc-node");
    });

    it("should send Authorization header", async () => {
      const litesoc = new LiteSOC({
        apiKey: "my-secret-key",
        fetch: mockFetch,
        batching: false,
      });

      await litesoc.track("auth.login_failed", { actor: "user_123" });

      const [, options] = mockFetch.mock.calls[0];
      expect(options.headers.Authorization).toBe("Bearer my-secret-key");
    });
  });

  describe("batching", () => {
    it("should batch events", async () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: true,
        batchSize: 3,
      });

      // Add events but don't await (they queue up)
      litesoc.track("auth.login_failed", { actor: "user_1" });
      litesoc.track("auth.login_failed", { actor: "user_2" });

      // Not sent yet
      expect(mockFetch).not.toHaveBeenCalled();
      expect(litesoc.getQueueSize()).toBe(2);

      // Third event triggers batch
      await litesoc.track("auth.login_failed", { actor: "user_3" });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [, options] = mockFetch.mock.calls[0];
      const body = JSON.parse(options.body);

      expect(body.events).toHaveLength(3);
    });

    it("should flush manually", async () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: true,
        batchSize: 100, // High batch size
      });

      litesoc.track("auth.login_failed", { actor: "user_1" });
      litesoc.track("auth.login_failed", { actor: "user_2" });

      expect(mockFetch).not.toHaveBeenCalled();

      await litesoc.flush();

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(litesoc.getQueueSize()).toBe(0);
    });

    it("should clear queue", () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: true,
      });

      litesoc.track("auth.login_failed", { actor: "user_1" });
      litesoc.track("auth.login_failed", { actor: "user_2" });

      expect(litesoc.getQueueSize()).toBe(2);

      litesoc.clearQueue();

      expect(litesoc.getQueueSize()).toBe(0);
    });
  });

  describe("convenience methods", () => {
    it("should track login failed", async () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: false,
      });

      await litesoc.trackLoginFailed("user_123", { userIp: "192.168.1.1" });

      const [, options] = mockFetch.mock.calls[0];
      const body = JSON.parse(options.body);

      expect(body.event).toBe("auth.login_failed");
      expect(body.actor.id).toBe("user_123");
    });

    it("should track privilege escalation with critical severity", async () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: false,
      });

      await litesoc.trackPrivilegeEscalation("user_123");

      const [, options] = mockFetch.mock.calls[0];
      const body = JSON.parse(options.body);

      expect(body.event).toBe("admin.privilege_escalation");
      expect(body.metadata._severity).toBe("critical");
    });

    it("should track bulk delete with record count", async () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: false,
      });

      await litesoc.trackBulkDelete("user_123", 500);

      const [, options] = mockFetch.mock.calls[0];
      const body = JSON.parse(options.body);

      expect(body.event).toBe("data.bulk_delete");
      expect(body.metadata.records_deleted).toBe(500);
    });

    it("should track role changed", async () => {
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
        batching: false,
      });

      await litesoc.trackRoleChanged("user_123", "user", "admin");

      const [, options] = mockFetch.mock.calls[0];
      const body = JSON.parse(options.body);

      expect(body.event).toBe("authz.role_changed");
      expect(body.metadata.old_role).toBe("user");
      expect(body.metadata.new_role).toBe("admin");
    });
  });

  describe("error handling", () => {
    it("should fail silently in silent mode", async () => {
      const failingFetch = vi.fn().mockRejectedValue(new Error("Network error"));
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: failingFetch,
        batching: false,
        silent: true,
      });

      // Should not throw
      await expect(
        litesoc.track("auth.login_failed", { actor: "user_123" })
      ).resolves.toBeUndefined();
    });

    it("should throw in strict mode", async () => {
      const failingFetch = vi.fn().mockRejectedValue(new Error("Network error"));
      const litesoc = new LiteSOC({
        apiKey: "test-key",
        fetch: failingFetch,
        batching: false,
        silent: false,
      });

      await expect(
        litesoc.track("auth.login_failed", { actor: "user_123" })
      ).rejects.toThrow("Network error");
    });
  });

  describe("createLiteSOC factory", () => {
    it("should create instance", () => {
      const litesoc = createLiteSOC({
        apiKey: "test-key",
        fetch: mockFetch,
      });

      expect(litesoc).toBeInstanceOf(LiteSOC);
    });
  });
});
