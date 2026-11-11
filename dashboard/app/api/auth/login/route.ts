import { NextRequest, NextResponse } from "next/server";
import { API_URL, COOKIE, csrfOk, forbidden } from "@/lib/server";

export async function POST(req: NextRequest) {
  if (!csrfOk(req)) return forbidden();
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: { message: "Invalid JSON" } }, { status: 400 });
  }
  let upstream: Response;
  try {
    upstream = await fetch(`${API_URL}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
    });
  } catch {
    return NextResponse.json({ error: { message: "API unreachable" } }, { status: 502 });
  }
  const data = await upstream.json().catch(() => ({}));
  if (!upstream.ok) {
    const res = NextResponse.json(data, { status: upstream.status });
    const ra = upstream.headers.get("retry-after");
    if (ra) res.headers.set("retry-after", ra);
    return res;
  }
  const maxAge = Math.max(1, Math.floor((new Date(data.expires_at).getTime() - Date.now()) / 1000));
  const res = NextResponse.json({ username: data.username, role: data.role });
  // The token never reaches page JavaScript: httpOnly + SameSite=Strict.
  res.cookies.set(COOKIE, data.access_token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.AVERQON_INSECURE_COOKIES !== "1" && process.env.NODE_ENV === "production",
    path: "/",
    maxAge,
  });
  return res;
}
