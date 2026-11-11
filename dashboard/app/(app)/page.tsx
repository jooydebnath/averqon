"use client";
import { useState } from "react";
import { BarChart, Meter } from "@/components/charts";
import { Header, Sev, Stat, StateView, fmtTime } from "@/components/ui";
import type { Page } from "@/lib/api";
import { useApi, useEventStream } from "@/lib/hooks";

interface Status { version: string; firewall: { backend: string; installed: boolean; counters: { packets?: number; bytes?: number } }; rules: number; active_bans: number; events_24h: number }
interface Health { ok: boolean; checks: Record<string, { ok: boolean }>; system: { cpu_percent: number; memory: { percent: number }; disk: { percent: number }; load_avg: number[] }; capabilities: { distro_id: string; kernel: string; nft_version: string | null } }
interface Stats { by_severity: Record<string, number>; by_kind: Record<string, number>; top_sources: { ip: string; count: number }[] }
interface Ev { id: number; ts: string; kind: string; severity: string; source_ip: string; message: string; action: string }

export default function Overview() {
  const st = useApi<Status>("status", { pollMs: 10000 });
  const hl = useApi<Health>("system/health", { pollMs: 10000 });
  const stats = useApi<Stats>("ids/stats?hours=24", { pollMs: 30000 });
  const recent = useApi<Page<Ev>>("ids/events?limit=8");
  const [live, setLive] = useState<Ev[]>([]);
  const conn = useEventStream((e) => setLive((l) => [e, ...l].slice(0, 8)));
  const feed = live.length ? live : recent.data?.items ?? [];
  const sys = hl.data?.system;
  return (
    <>
      <Header title="Overview" sub="Live state of this host" actions={<span className="live"><i className={`dot ${conn === "live" ? "on" : ""}`} />{conn === "live" ? "live" : conn}</span>} />
      <StateView loading={st.loading} error={st.error} onRetry={st.reload}>
        {st.data && (
          <div className="grid g4">
            <Stat label="Firewall" value={st.data.firewall.installed ? "Active" : "Not installed"} hint={st.data.firewall.backend} />
            <Stat label="Rules" value={st.data.rules} />
            <Stat label="Active bans" value={st.data.active_bans} />
            <Stat label="Events (24h)" value={st.data.events_24h} />
            <Stat label="Packets matched" value={(st.data.firewall.counters.packets ?? 0).toLocaleString()} hint="counter rules" />
          </div>
        )}
      </StateView>
      <div className="grid g2" style={{ marginTop: 14 }}>
        <div className="card"><h2>System health {hl.data && <span className={`badge ${hl.data.ok ? "b-ok" : "b-bad"}`}>{hl.data.ok ? "healthy" : "degraded"}</span>}</h2>
          <StateView loading={hl.loading} error={hl.error} onRetry={hl.reload}>
            {sys && hl.data && (<div className="grid">
              {([["CPU", sys.cpu_percent], ["Memory", sys.memory.percent], ["Disk", sys.disk.percent]] as const).map(([n, v]) => (
                <div key={n}><div className="row" style={{ justifyContent: "space-between" }}><span>{n}</span><span>{v.toFixed(0)}%</span></div><Meter percent={v} /></div>))}
              <div className="sub">{hl.data.capabilities.distro_id} · kernel {hl.data.capabilities.kernel} · nft {hl.data.capabilities.nft_version ?? "n/a"} · load {sys.load_avg.map((l) => l.toFixed(2)).join(" ")}</div>
              <div className="row">{Object.entries(hl.data.checks).map(([k, c]) => <span key={k} className={`badge ${c.ok ? "b-ok" : "b-bad"}`}>{k}</span>)}</div>
            </div>)}
          </StateView></div>
        <div className="card"><h2>Events by severity (24h)</h2>
          <StateView loading={stats.loading} error={stats.error}>
            <BarChart data={["low", "medium", "high", "critical"].map((s) => ({ label: s, value: stats.data?.by_severity[s] ?? 0 }))} colors={{ low: "#8b97b3", medium: "#e0a526", high: "#e5484d", critical: "#b4308b" }} />
          </StateView></div>
      </div>
      <div className="grid g2" style={{ marginTop: 14 }}>
        <div className="card"><h2>Latest events</h2>
          {feed.length === 0 ? <div className="state">No events recorded.</div> : (
            <div className="tw"><table><tbody>{feed.map((e) => (
              <tr key={e.id}><td className="sub">{fmtTime(e.ts)}</td><td><Sev s={e.severity} /></td><td>{e.kind}</td><td className="mono">{e.source_ip}</td><td className="sub">{e.action}</td></tr>))}</tbody></table></div>)}
        </div>
        <div className="card"><h2>Top sources (24h)</h2>
          {!stats.data?.top_sources.length ? <div className="state">No sources recorded.</div> : (
            <table><tbody>{stats.data.top_sources.map((s) => <tr key={s.ip}><td className="mono">{s.ip}</td><td>{s.count}</td></tr>)}</tbody></table>)}
        </div>
      </div>
    </>
  );
}
