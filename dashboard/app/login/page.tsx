"use client";
import { useState } from "react";

export default function Login() {
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const f = new FormData(e.currentTarget);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json", "x-averqon-csrf": "1" },
        body: JSON.stringify({ username: f.get("username"), password: f.get("password") }),
      });
      if (res.ok) { window.location.href = "/"; return; }
      const d = await res.json().catch(() => null);
      setErr(res.status === 429 ? `Too many attempts. Retry in ${res.headers.get("retry-after") ?? "a minute"}s.` : (d?.error?.message ?? "Sign-in failed"));
    } catch { setErr("Cannot reach the server"); } finally { setBusy(false); }
  }
  return (
    <div className="login"><div className="card">
      <div className="brand">Aver<span>qon</span></div>
      <form onSubmit={submit}>
        {err && <div className="err" role="alert">{err}</div>}
        <label>Username<input name="username" autoComplete="username" required maxLength={64} autoFocus /></label>
        <label>Password<input name="password" type="password" autoComplete="current-password" required maxLength={256} /></label>
        <button disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </div></div>
  );
}
