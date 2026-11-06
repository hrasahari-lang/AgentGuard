import assert from "node:assert/strict";
import test from "node:test";
import {
  clearPrivilegedSessionOnRequestFailure,
  GatewayAuthenticationError,
  requestGatewayJson,
  resolveGatewayOrigin,
} from "../src/gatewaySecurity.ts";

test("accepts the configured HTTPS origin and loopback HTTP for development", () => {
  assert.deepEqual(resolveGatewayOrigin("https://gateway.example.com"), {
    origin: "https://gateway.example.com",
    error: null,
  });
  assert.equal(resolveGatewayOrigin("http://127.0.0.1:8000").origin, "http://127.0.0.1:8000");
});

test("missing, malformed, insecure remote, and ambiguous origin configuration fails safely", () => {
  for (const value of [undefined, "", "not a url", "http://gateway.example.com", "https://gateway.example.com/path", "https://0x7f000001"]) {
    const config = resolveGatewayOrigin(value);
    assert.equal(config.origin, null, String(value));
    assert.ok(config.error, String(value));
  }
});

test("production origins require HTTPS and an explicitly approved DNS hostname", () => {
  const production = {
    production: true,
    approvedHostnames: "api.agentguard.example,staging.agentguard.example",
  };
  assert.equal(
    resolveGatewayOrigin("https://api.agentguard.example", production).origin,
    "https://api.agentguard.example",
  );

  for (const origin of [
    "http://127.0.0.1:8000",
    "https://127.0.0.1",
    "https://localhost",
    "https://attacker.example",
    "https://api.agentguard.example:8443",
  ]) {
    assert.equal(resolveGatewayOrigin(origin, production).origin, null, origin);
  }
  assert.equal(
    resolveGatewayOrigin("https://api.agentguard.example", { production: true }).origin,
    null,
    "production fails closed when the hostname allowlist is missing",
  );
});

test("requests attach the bearer only to the configured origin", async () => {
  const config = resolveGatewayOrigin("https://gateway.example.com");
  const calls = [];
  const fetcher = async (url, options) => {
    calls.push({ url: String(url), options });
    return { ok: true, status: 200, json: async () => ({ events: [] }) };
  };

  await requestGatewayJson(config, "admin-secret", "/api/audit?limit=250", fetcher);
  assert.equal(calls.length, 1);
  assert.equal(new URL(calls[0].url).origin, config.origin);
  assert.equal(calls[0].options.headers.Authorization, "Bearer admin-secret");
  assert.equal(calls[0].options.redirect, "error");

  await assert.rejects(
    requestGatewayJson(config, "admin-secret", "https://attacker.example/collect", fetcher),
    /relative to the configured origin/,
  );
  await assert.rejects(
    requestGatewayJson(resolveGatewayOrigin(undefined), "admin-secret", "/api/overview", fetcher),
    /Set VITE_AGENTGUARD_API_ORIGIN/,
  );
  assert.equal(calls.length, 1, "no request or Authorization header reaches an untrusted origin");
});

test("authentication, server, and network failures clear privileged session state", async () => {
  const config = resolveGatewayOrigin("https://gateway.example.com");
  for (const failure of [
    ...[401, 403].map((status) => ({
      run: () => requestGatewayJson(config, "admin-secret", "/api/overview", async () => ({
        ok: false,
        status,
        json: async () => ({}),
      })),
      check: (error) => error instanceof GatewayAuthenticationError && error.status === status,
    })),
    {
      run: () => requestGatewayJson(config, "admin-secret", "/api/overview", async () => ({
        ok: false,
        status: 503,
        json: async () => ({}),
      })),
      check: (error) => error instanceof Error && /503/.test(error.message),
    },
    {
      run: () => requestGatewayJson(config, "admin-secret", "/api/overview", async () => {
        throw new TypeError("Network unavailable");
      }),
      check: (error) => error instanceof TypeError && /Network unavailable/.test(error.message),
    },
  ]) {
    await assert.rejects(failure.run(), failure.check);
    const session = { data: { audit: ["private"] }, token: "admin-secret", origin: config.origin, updatedAt: 1 };
    clearPrivilegedSessionOnRequestFailure(() => {
      session.data = null;
      session.token = "";
      session.origin = null;
      session.updatedAt = null;
    });
    assert.deepEqual(session, { data: null, token: "", origin: null, updatedAt: null });
  }
});
