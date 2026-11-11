import { NextRequest } from "next/server";
import { API_URL, COOKIE, csrfOk, forbidden } from "@/lib/server";

export const dynamic = "force-dynamic";
const PASS_HEADERS = ["content-type", "retry-after", "x-request-id"];

async function handle(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }): Promise<Response> {
  if (!csrfOk(req)) return forbidden();
  const { path } = await ctx.params;
  if (path.some((p) => p === ".." || p === "." || p.includes("\\"))) {
    return Response.json({ error: { message: "Bad path" } }, { status: 400 });
  }
  const token = req.cookies.get(COOKIE)?.value;
  const url = `${API_URL}/api/v1/${path.map(encodeURIComponent).join("/")}${req.nextUrl.search}`;
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  const ct = req.headers.get("content-type");
  if (ct) headers["content-type"] = ct;
  const hasBody = !["GET", "HEAD"].includes(req.method);
  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method: req.method,
      headers,
      body: hasBody ? await req.arrayBuffer() : undefined,
      cache: "no-store",
      signal: req.signal,
    });
  } catch {
    return Response.json({ error: { message: "API unreachable" } }, { status: 502 });
  }
  const out = new Headers();
  for (const h of PASS_HEADERS) {
    const v = upstream.headers.get(h);
    if (v) out.set(h, v);
  }
  out.set("cache-control", "no-store");
  const res = new Response(upstream.status === 204 ? null : upstream.body, { status: upstream.status, headers: out });
  if (upstream.status === 401 && token) res.headers.append("set-cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict`);
  return res;
}

export { handle as GET, handle as POST, handle as PUT, handle as PATCH, handle as DELETE };
