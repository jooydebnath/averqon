"use client";
import { useState } from "react";
import { Header, Pager, Sev, StateView, fmtTime } from "@/components/ui";
import type { Page } from "@/lib/api";
import { useApi, useEventStream, usePaging } from "@/lib/hooks";

interface Ev { id: number; ts: string; kind: string; severity: string; source_ip: string; jail: string | null; message: string; action: string }

export default function Events() {
  const p = usePaging(25);
  const [sev, setSev] = useState("");
  const [kind, setKind] = useState("");
  const [ip, setIp] = useState("");
  const [fresh, setFresh] = useState(0);
  const qs = new URLSearchParams({ limit: String(p.limit), offset: String(p.offset) });
  if (sev) qs.set("severity", sev);
  if (kind) qs.set("kind", kind);
  if (ip) qs.set("source_ip", ip);
  const { data, error, loading, reload } = useApi<Page<Ev>>(`ids/events?${qs}`);
  const conn = useEventStream(() => setFresh((n) => n + 1));
  return (
    <>
      <Header title="IDS / IPS events" sub="Detections and the action taken" actions={<span className="live"><i className={`dot ${conn === "live" ? "on" : ""}`} />{conn}</span>} />
      <div className="card">
        <div className="row" style={{ marginBottom: 12 }}>
          <label>Severity<select value={sev} onChange={(e) => { setSev(e.target.value); p.setOffset(0); }}><option value="">all</option>{["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}</select></label>
          <label>Kind<input value={kind} onChange={(e) => { setKind(e.target.value.toLowerCase()); p.setOffset(0); }} placeholder="port_scan" pattern="[a-z_]*" /></label>
          <label>Source IP<input value={ip} onChange={(e) => { setIp(e.target.value.trim()); p.setOffset(0); }} placeholder="203.0.113.5" /></label>
          {fresh > 0 && <button onClick={() => { setFresh(0); reload(); }}>{fresh} new — refresh</button>}
        </div>
        <StateView loading={loading} error={error} onRetry={reload} empty={data?.total === 0}>
          {data && <div className="tw"><table><thead><tr><th>Time</th><th>Severity</th><th>Kind</th><th>Source</th><th>Jail</th><th>Action</th><th>Message</th></tr></thead>
            <tbody>{data.items.map((e) => <tr key={e.id}><td className="sub">{fmtTime(e.ts)}</td><td><Sev s={e.severity} /></td><td>{e.kind}</td><td className="mono">{e.source_ip}</td><td>{e.jail ?? "—"}</td><td>{e.action}</td><td className="sub">{e.message}</td></tr>)}</tbody></table></div>}
          {data && <Pager total={data.total} limit={p.limit} offset={p.offset} onChange={p.setOffset} />}
        </StateView>
      </div>
    </>
  );
}
