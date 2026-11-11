"use client";
import { useState } from "react";
import { Header, StateView, Badge } from "@/components/ui";
import { useApi } from "@/lib/hooks";

interface Conn { proto: string; family: string; local: string; remote: string; state: string; pid: number | null }
interface Resp { items: Conn[]; total: number; by_state: Record<string, number>; error?: string }

export default function Connections() {
  const { data, error, loading, reload } = useApi<Resp>("network/connections?limit=500", { pollMs: 3000 });
  const [q, setQ] = useState("");
  const [state, setState] = useState("");
  const rows = (data?.items ?? []).filter((c) => (!state || c.state === state) && (!q || `${c.local} ${c.remote}`.includes(q)));
  return (
    <>
      <Header title="Live connections" sub="Refreshes every 3 seconds. Process IDs need root." />
      <div className="card">
        <div className="row" style={{ marginBottom: 12 }}>
          <label>Filter address<input value={q} onChange={(e) => setQ(e.target.value)} placeholder="10.0.0.1 or :22" /></label>
          <label>State<select value={state} onChange={(e) => setState(e.target.value)}><option value="">all</option>{Object.keys(data?.by_state ?? {}).map((s) => <option key={s}>{s}</option>)}</select></label>
          <span className="sub">{rows.length} shown / {data?.total ?? 0} total</span>
        </div>
        {data?.error && <div className="err">{data.error}</div>}
        <StateView loading={loading} error={error} onRetry={reload}>
          <div className="tw"><table><thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th><th>PID</th></tr></thead>
            <tbody>{rows.slice(0, 300).map((c, i) => <tr key={i}><td>{c.proto}{c.family === "ipv6" ? "6" : ""}</td><td className="mono">{c.local}</td><td className="mono">{c.remote || "—"}</td><td><Badge kind={c.state === "ESTABLISHED" ? "ok" : "acc"}>{c.state || "—"}</Badge></td><td>{c.pid ?? "—"}</td></tr>)}</tbody></table></div>
          {rows.length === 0 && <div className="state">No matching connections.</div>}
        </StateView>
      </div>
    </>
  );
}
