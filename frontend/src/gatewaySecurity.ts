export type GatewayOriginConfig = {
  origin: string | null;
  error: string | null;
};

export class GatewayAuthenticationError extends Error {
  readonly status: 401 | 403;

  constructor(status: 401 | 403) {
    super(status === 401 ? "Authentication failed. Check the admin credential." : "This credential does not have the admin role.");
    this.name = "GatewayAuthenticationError";
    this.status = status;
  }
}

export function resolveGatewayOrigin(value: unknown): GatewayOriginConfig {
  if (typeof value !== "string" || !value || value !== value.trim()) {
    return { origin: null, error: "Set VITE_AGENTGUARD_API_ORIGIN to the trusted gateway origin." };
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return { origin: null, error: "The configured gateway origin is invalid." };
  }

  const authorityStart = value.indexOf("://") + 3;
  const rawAuthority = value.slice(authorityStart).split(/[/?#]/, 1)[0];
  const hostname = parsed.hostname.toLowerCase();
  const canonicalAuthority = parsed.host.toLowerCase();
  const isLoopback = hostname === "localhost"
    || hostname === "[::1]"
    || /^127(?:\.\d{1,3}){3}$/.test(hostname)
      && hostname.split(".").slice(1).every((part) => Number(part) <= 255);

  if (
    !["https:", "http:"].includes(parsed.protocol)
    || parsed.username
    || parsed.password
    || parsed.pathname !== "/"
    || parsed.search
    || parsed.hash
    || value.includes("?")
    || value.includes("#")
    || hostname.endsWith(".")
    || rawAuthority.toLowerCase() !== canonicalAuthority
  ) {
    return { origin: null, error: "Configure a canonical gateway origin without paths, credentials, queries, or fragments." };
  }
  if (parsed.protocol === "http:" && !isLoopback) {
    return { origin: null, error: "Remote gateway origins must use HTTPS." };
  }

  return { origin: parsed.origin, error: null };
}

export async function requestGatewayJson<T>(
  config: GatewayOriginConfig,
  token: string,
  path: string,
  fetcher: typeof fetch = fetch,
): Promise<T> {
  if (!config.origin) {
    throw new Error(config.error ?? "The trusted gateway origin is unavailable.");
  }
  if (!path.startsWith("/") || path.startsWith("//")) {
    throw new Error("Gateway API paths must be relative to the configured origin.");
  }

  let target: URL;
  try {
    target = new URL(path, `${config.origin}/`);
  } catch {
    throw new Error("Gateway API path is invalid.");
  }
  if (target.origin !== config.origin) {
    throw new Error("Gateway API path escaped the configured origin.");
  }

  const response = await fetcher(target, {
    redirect: "error",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  const body = (await response.json().catch(() => ({}))) as { error?: string } & T;
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new GatewayAuthenticationError(response.status);
    }
    throw new Error(body.error ?? `AgentGuard returned HTTP ${response.status}.`);
  }
  return body;
}

export function clearPrivilegedSessionOnAuthFailure(
  status: number,
  clear: () => void,
): boolean {
  if (status !== 401 && status !== 403) return false;
  clear();
  return true;
}
