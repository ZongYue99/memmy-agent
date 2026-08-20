import { describe, expect, it, vi } from "vitest";
import { EgressClient } from "../../../../src/core/agent-runtime/sandbox/adapters/execution/egress-client.js";

const publicAddress = [{ address: "93.184.216.34", family: 4 as const }];

describe("EgressClient", () => {
  it("checks policy and private DNS results before making a request", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const client = new EgressClient(undefined, {
      resolve: async () => [{ address: "127.0.0.1", family: 4 }],
      fetchImpl,
    });

    await expect(
      client.request({ url: "https://example.com", policy: { mode: "unrestricted" } }),
    ).rejects.toThrow("egress-private-address-denied");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("pins DNS and disables automatic redirects", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response("ok", { status: 200 }));
    const client = new EgressClient(undefined, {
      resolve: async () => publicAddress,
      fetchImpl,
    });

    await expect(
      client.request({ url: "https://example.com/data", policy: { mode: "unrestricted" } }),
    ).resolves.toMatchObject({ status: 200, body: new TextEncoder().encode("ok") });
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fetchImpl.mock.calls[0]?.[1]).toMatchObject({ redirect: "manual" });
    expect(fetchImpl.mock.calls[0]?.[1]).toHaveProperty("dispatcher");
  });

  it("rejects caller-controlled hop-by-hop headers", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const client = new EgressClient(undefined, {
      resolve: async () => publicAddress,
      fetchImpl,
    });

    await expect(
      client.request({
        url: "https://example.com",
        policy: { mode: "unrestricted" },
        headers: { Host: "internal.example" },
      }),
    ).rejects.toThrow("egress-header-denied");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("bounds response bodies", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(new Uint8Array([1, 2, 3])));
    const client = new EgressClient(undefined, {
      resolve: async () => publicAddress,
      fetchImpl,
      maxResponseBytes: 2,
    });

    await expect(
      client.request({ url: "https://example.com", policy: { mode: "unrestricted" } }),
    ).rejects.toThrow("egress-response-too-large");
  });
});
