import assert from "node:assert/strict";
import test from "node:test";
import {
  clearPrivilegedSessionOnAuthFailure,
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

test("401 and 403 clear privileged session state while other errors do not", async () => {
  const config = resolveGatewayOrigin("https://gateway.example.com");
  for (const status of [401, 403]) {
    const authFailure = requestGatewayJson(config, "admin-secret", "/api/overview", async () => ({
      ok: false,
      status,
      json: async () => ({}),
    }));
    await assert.rejects(authFailure, (error) => error instanceof GatewayAuthenticationError && error.status === status);

    const session = { data: { audit: ["private"] }, token: "admin-secret", origin: config.origin, updatedAt: 1 };
    const cleared = clearPrivilegedSessionOnAuthFailure(status, () => {
      session.data = null;
      session.token = "";
      session.origin = null;
      session.updatedAt = null;
    });
    assert.equal(cleared, true);
    assert.deepEqual(session, { data: null, token: "", origin: null, updatedAt: null });
  }

  let cleared = false;
  assert.equal(clearPrivilegedSessionOnAuthFailure(503, () => { cleared = true; }), false);
  assert.equal(cleared, false);
});
