import { NextRequest } from "next/server";

export const API_URL = process.env.AVERQON_API_URL ?? "http://127.0.0.1:8443";
export const COOKIE = "averqon_session";

/** CSRF defence for cookie-authenticated requests: same-origin + custom header (cannot be set cross-site without CORS). */
export function csrfOk(req: NextRequest): boolean {
  if (req.method === "GET" || req.method === "HEAD") return true;
  const origin = req.headers.get("origin");
  const host = req.headers.get("host");
  if (!origin || !host) return false;
  try {
    if (new URL(origin).host !== host) return false;
  } catch {
    return false;
  }
  return req.headers.get("x-averqon-csrf") === "1";
}

/**
 * Pass the client address chain set by the reverse proxy in front of the dashboard on to the API, so
 * per-client rate limits and audit logs see the real client (the API only trusts it from `api.trusted_proxies`).
 */
export function forwardedFor(req: NextRequest): Record<string, string> {
  const xff = req.headers.get("x-forwarded-for");
  return xff ? { "x-forwarded-for": xff } : {};
}

export function forbidden(): Response {
  return Response.json({ error: { code: "csrf", message: "Cross-site request rejected" } }, { status: 403 });
}
