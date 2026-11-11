"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { AuthProvider, type Me } from "@/lib/hooks";
import { Spinner } from "@/components/ui";

const NAV: { href: string; label: string; perm: string }[] = [
  { href: "/", label: "Overview", perm: "status:read" },
  { href: "/rules", label: "Firewall rules", perm: "rules:read" },
  { href: "/connections", label: "Live connections", perm: "network:read" },
  { href: "/events", label: "IDS / IPS events", perm: "events:read" },
  { href: "/bans", label: "Banned IPs", perm: "bans:read" },
  { href: "/whitelist", label: "Whitelist", perm: "whitelist:read" },
  { href: "/network", label: "Network monitoring", perm: "network:read" },
  { href: "/analytics", label: "Security analytics", perm: "analytics:read" },
  { href: "/audit", label: "Audit logs", perm: "audit:read" },
  { href: "/settings", label: "System settings", perm: "settings:read" },
  { href: "/users", label: "Users & roles", perm: "users:manage" },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const path = usePathname();
  useEffect(() => { api<Me>("auth/me").then(setMe).catch(() => undefined); }, []);
  if (!me) return <div className="state" style={{ paddingTop: 120 }}><Spinner />Loading…</div>;
  async function logout() {
    await fetch("/api/auth/logout", { method: "POST", headers: { "x-averqon-csrf": "1" } });
    window.location.href = "/login";
  }
  return (
    <AuthProvider me={me}>
      <div className="shell">
        <aside className="side">
          <div className="brand">Aver<span>qon</span></div>
          <nav className="nav">
            {NAV.filter((n) => me.permissions.includes(n.perm)).map((n) => (
              <Link key={n.href} href={n.href} className={path === n.href ? "on" : ""}>{n.label}</Link>
            ))}
          </nav>
          <div style={{ padding: "18px 10px 0" }} className="sub">
            <div>{me.username}</div><div><span className="badge b-acc">{me.role}</span></div>
            <button className="sec sm" style={{ marginTop: 10 }} onClick={logout}>Sign out</button>
          </div>
        </aside>
        <main className="main">{children}</main>
      </div>
    </AuthProvider>
  );
}
