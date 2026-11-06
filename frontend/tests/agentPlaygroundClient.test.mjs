import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import test from "node:test";
import {
  callAgentTool,
  classifyToolResult,
  connectAgentGateway,
  decisionFromAudit,
  digestRequestId,
  getToolText,
  safeAgentError,
  validateCustomerId,
  validateExportInput,
  validateSearchInput,
} from "../src/agentPlaygroundClient.ts";
import { resolveGatewayOrigin } from "../src/gatewaySecurity.ts";

const gateway = resolveGatewayOrigin("https://gateway.example.com", {
  production: true,
  approvedHostnames: "gateway.example.com",
});
const newTestToken = () => randomBytes(32).toString("base64url");

function jsonRpcResponse(id, result) {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id, result }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

test("uses MCP Streamable HTTP initialization, discovery, and authenticated tool calls", async () => {
  const agentToken = newTestToken();
  const requests = [];
  const fetcher = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const body = request.method === "POST" ? await request.json() : null;
    requests.push({ request, url, body });

    if (body?.method === "initialize") {
      return jsonRpcResponse(body.id, {
        protocolVersion: body.params.protocolVersion,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "AgentGuard", version: "0.1.0" },
      });
    }
    if (body?.method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }
    if (body?.method === "tools/list") {
      return jsonRpcResponse(body.id, {
        tools: [{
          name: "search_customer_records",
          description: "Search scoped customer records.",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string" },
              limit: { type: "integer" },
              request_id: { type: "string" },
            },
            required: ["query"],
          },
        }],
      });
    }
    if (body?.method === "tools/call") {
      return jsonRpcResponse(body.id, {
        content: [{ type: "text", text: "[{\"customer_id\":\"CUST-101\"}]" }],
        isError: false,
      });
    }
    throw new Error(`Unexpected MCP request: ${body?.method ?? request.method}`);
  };

  const session = await connectAgentGateway(gateway, agentToken, fetcher);
  assert.deepEqual(session.tools.map(({ name }) => name), ["search_customer_records"]);
  assert.equal(session.tools[0].description, "Search scoped customer records.");

  const result = await callAgentTool(session.client, "search_customer_records", {
    ...validateSearchInput("  Acme  ", 5),
    request_id: "playground-test-request-1",
  });
  assert.equal(classifyToolResult(result), "ALLOW");
  assert.equal(getToolText(result), '[{"customer_id":"CUST-101"}]');

  assert.ok(requests.some(({ body }) => body?.method === "initialize"));
  assert.ok(requests.some(({ body }) => body?.method === "tools/list"));
  assert.ok(requests.some(({ body }) => body?.method === "tools/call"));
  for (const { request, url } of requests) {
    assert.equal(url.origin, gateway.origin);
    assert.equal(url.pathname, "/mcp");
    assert.equal(request.headers.get("authorization"), "Bearer " + agentToken);
    assert.equal(request.redirect, "error");
  }
  const toolCall = requests.find(({ body }) => body?.method === "tools/call");
  assert.equal(toolCall.body.params.arguments.request_id, "playground-test-request-1");
  await session.client.close();
});

test("Streamable HTTP rejects redirect responses without following them", async () => {
  const attemptedUrls = [];
  const agentToken = newTestToken();
  const fetcher = async (input, init) => {
    const request = new Request(input, init);
    attemptedUrls.push(request.url);
    return new Response(null, {
      status: 307,
      headers: { location: "https://attacker.example/collect" },
    });
  };

  await assert.rejects(
    connectAgentGateway(gateway, agentToken, fetcher),
    /redirect|HTTP|response|failed/i,
  );
  assert.deepEqual(attemptedUrls, ["https://gateway.example.com/mcp"]);
});

test("origin and bearer validation fail before constructing a request", async () => {
  let fetchCount = 0;
  const fetcher = async () => {
    fetchCount += 1;
    throw new Error("unexpected network request");
  };

  await assert.rejects(connectAgentGateway({ origin: null, error: "not trusted" }, newTestToken(), fetcher), /not trusted/);
  await assert.rejects(connectAgentGateway(gateway, "  ", fetcher), /demo-agent bearer/);
  const invalidGateway = { origin: "https://attacker.example/path", error: null };
  await assert.rejects(connectAgentGateway(invalidGateway, newTestToken(), fetcher), /not trusted/);
  assert.equal(fetchCount, 0);
});

test("policy outcomes remain distinct from unclassified tool failures", () => {
  const result = (text) => ({ content: [{ type: "text", text }], isError: true });
  assert.equal(classifyToolResult({ content: [], isError: false }), "ALLOW");
  assert.equal(classifyToolResult(result("Request denied by AgentGuard policy.")), "DENY");
  assert.equal(
    classifyToolResult(result("Request requires human approval; protected data was not accessed.")),
    "REQUIRE_APPROVAL",
  );
  assert.equal(classifyToolResult(result("Credential rejected.")), "UNKNOWN");
});

test("input validation, audit correlation, and error redaction are bounded", async () => {
  assert.deepEqual(validateSearchInput(" Acme ", 10), { query: "Acme", limit: 10 });
  assert.throws(() => validateSearchInput(" ", 10), /search term/);
  assert.throws(() => validateSearchInput("Acme", 101), /1 to 100/);
  assert.deepEqual(validateCustomerId(" CUST-101 "), { customer_id: "CUST-101" });
  assert.throws(() => validateCustomerId("id\nwith-control"), /printable/);
  assert.deepEqual(validateExportInput("csv", 101), { format: "csv", limit: 101 });
  assert.throws(() => validateExportInput("xml", 10), /JSON or CSV/);
  assert.throws(() => validateExportInput("json", 1001), /1 to 1000/);

  const requestId = "playground-audit-correlation-1";
  const digest = await digestRequestId(requestId);
  assert.equal(digest, createHash("sha256").update(requestId).digest("hex"));
  const event = { request_id: digest, decision: "REQUIRE_APPROVAL", execution_status: "PENDING_APPROVAL" };
  assert.equal(decisionFromAudit([event], digest), event);
  assert.equal(decisionFromAudit([], digest), undefined);
  const redactionToken = newTestToken();
  assert.equal(safeAgentError(new Error("Rejected Bearer " + redactionToken), redactionToken), "Rejected Bearer [credential redacted]");
});
