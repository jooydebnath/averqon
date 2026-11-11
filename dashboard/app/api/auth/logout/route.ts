import { NextRequest, NextResponse } from "next/server";
import { API_URL, COOKIE, csrfOk, forbidden } from "@/lib/server";

export async function POST(req: NextRequest) {
  if (!csrfOk(req)) return forbidden();
  const token = req.cookies.get(COOKIE)?.value;
  if (token) {
    await fetch(`${API_URL}/api/v1/auth/logout`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
      cache: "no-store",
    }).catch(() => undefined);
  }
  const res = NextResponse.json({ ok: true });
  res.cookies.set(COOKIE, "", { httpOnly: true, sameSite: "strict", path: "/", maxAge: 0 });
  return res;
}
