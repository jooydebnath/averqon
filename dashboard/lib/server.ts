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

export function forbidden(): Response {
  return Response.json({ error: { code: "csrf", message: "Cross-site request rejected" } }, { status: 403 });
}
