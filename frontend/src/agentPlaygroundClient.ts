import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import type { CallToolResult, Tool } from "@modelcontextprotocol/client";
import type { GatewayOriginConfig } from "./gatewaySecurity";

export type AgentToolSummary = Pick<Tool, "name" | "description">;
export type AgentMcpConnection = {
  client: Client;
  tools: AgentToolSummary[];
};
export type PlaygroundDecision = "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "UNKNOWN";
export type PlaygroundAuditEvent = {
  request_id?: string | null;
  decision: string;
  execution_status: string;
};

export async function connectAgentGateway(
  gateway: GatewayOriginConfig,
  bearerToken: string,
  fetcher: typeof fetch = fetch,
): Promise<AgentMcpConnection> {
  if (!gateway.origin) {
    throw new Error(gateway.error ?? "The trusted AgentGuard gateway is unavailable.");
  }
  const token = bearerToken.trim();
  if (!token) throw new Error("Enter the demo-agent bearer credential.");

  let trustedOrigin: URL;
  try {
    trustedOrigin = new URL(gateway.origin);
  } catch {
    throw new Error("The configured AgentGuard gateway origin is invalid.");
  }
  if (
    trustedOrigin.origin !== gateway.origin
    || !["https:", "http:"].includes(trustedOrigin.protocol)
    || (trustedOrigin.protocol === "http:" && !isLoopbackHost(trustedOrigin.hostname))
  ) {
    throw new Error("The configured AgentGuard gateway origin is not trusted.");
  }

  const endpoint = new URL("/mcp", trustedOrigin.origin);
  if (endpoint.origin !== trustedOrigin.origin || endpoint.pathname !== "/mcp") {
    throw new Error("The configured MCP endpoint is invalid.");
  }

  const client = new Client({ name: "agentguard-playground", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(endpoint, {
    authProvider: { token: async () => token },
    fetch: fetcher,
    requestInit: { redirect: "error" },
    redirectPolicy: "same-origin",
  });

  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    return {
      client,
      tools: tools.map(({ name, description }) => ({ name, description })),
    };
  } catch (error) {
    await closeAgentGateway(client);
    throw error;
  }
}

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return host === "localhost" || host === "[::1]"
    || /^127(?:\.\d{1,3}){3}$/.test(host)
      && host.slice(4).split(".").every((part) => Number(part) <= 255);
}

export async function closeAgentGateway(client: Client | null): Promise<void> {
  if (!client) return;
  try {
    await client.close();
  } catch {
    // Closing a short-lived playground transport is best-effort.
  }
}

export async function callAgentTool(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<CallToolResult> {
  return client.callTool({ name, arguments: args });
}

export function validateSearchInput(query: string, limit: number): { query: string; limit: number } {
  const normalizedQuery = query.trim();
  if (!normalizedQuery) throw new Error("Enter a search term.");
  if (normalizedQuery.length > 120) throw new Error("Search terms must be 120 characters or fewer.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new Error("Search limit must be a whole number from 1 to 100.");
  }
  return { query: normalizedQuery, limit };
}

export function validateCustomerId(customerId: string): { customer_id: string } {
  const normalizedId = customerId.trim();
  if (!normalizedId) throw new Error("Enter a customer ID.");
  if (normalizedId.length > 64 || /[\u0000-\u001f\u007f]/.test(normalizedId)) {
    throw new Error("Customer ID must be at most 64 printable characters.");
  }
  return { customer_id: normalizedId };
}

export function validateExportInput(format: string, limit: number): { format: "json" | "csv"; limit: number } {
  if (format !== "json" && format !== "csv") throw new Error("Choose JSON or CSV format.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
    throw new Error("Export limit must be a whole number from 1 to 1000.");
  }
  return { format, limit };
}

export function classifyToolResult(result: CallToolResult): PlaygroundDecision {
  if (!result.isError) return "ALLOW";
  const message = getToolText(result).toLowerCase();
  if (message.includes("request denied by agentguard policy")) return "DENY";
  if (message.includes("request requires human approval")) return "REQUIRE_APPROVAL";
  return "UNKNOWN";
}

export function getToolText(result: CallToolResult): string {
  return result.content
    .filter((block) => block.type === "text")
    .map((block) => block.text)
    .join("\n");
}

export async function digestRequestId(requestId: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(requestId));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function decisionFromAudit(
  events: PlaygroundAuditEvent[],
  requestIdDigest: string,
): PlaygroundAuditEvent | undefined {
  return events.find((event) => event.request_id === requestIdDigest);
}

export function safeAgentError(error: unknown, bearerToken: string): string {
  const message = error instanceof Error ? error.message : "The MCP request failed.";
  if (/failed to fetch|networkerror|load failed/i.test(message)) {
    return "Could not reach the MCP gateway. Check its availability, CORS configuration, and the demo-agent credential.";
  }
  return bearerToken ? message.split(bearerToken).join("[credential redacted]") : message;
}
