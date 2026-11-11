"use client";
import { useState } from "react";
import { Header, Pager, StateView, fmtTime } from "@/components/ui";
import type { Page } from "@/lib/api";
import { useApi, usePaging } from "@/lib/hooks";

interface A { id: number; ts: string; actor: string; action: string; target: string; outcome: string; source_ip: string; details: Record<string, unknown> }

export default function Audit() {
  const p = usePaging(25);
  const [actor, setActor] = useState(""); const [action, setAction] = useState(""); const [outcome, setOutcome] = useState("");
  const qs = new URLSearchParams({ limit: String(p.limit), offset: String(p.offset) });
  if (actor) qs.set("actor", actor); if (action) qs.set("action", action); if (outcome) qs.set("outcome", outcome);
  const { data, error, loading, reload } = useApi<Page<A>>(`audit/logs?${qs}`);
  return (
    <>
      <Header title="Audit logs" sub="Append-only record of administrative and security-relevant actions" />
      <div className="card">
        <div className="row" style={{ marginBottom: 12 }}>
          <label>Actor<input value={actor} onChange={(e) => { setActor(e.target.value); p.setOffset(0); }} /></label>
          <label>Action<input value={action} onChange={(e) => { setAction(e.target.value); p.setOffset(0); }} placeholder="ip.ban" /></label>
          <label>Outcome<select value={outcome} onChange={(e) => { setOutcome(e.target.value); p.setOffset(0); }}><option value="">all</option><option>success</option><option>failure</option><option>denied</option></select></label>
        </div>
        <StateView loading={loading} error={error} onRetry={reload} empty={data?.total === 0}>
          {data && <div className="tw"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th><th>Source IP</th><th>Details</th></tr></thead>
            <tbody>{data.items.map((a) => <tr key={a.id}><td className="sub">{fmtTime(a.ts)}</td><td>{a.actor}</td><td>{a.action}</td><td className="mono">{a.target || "—"}</td><td><span className={`badge ${a.outcome === "success" ? "b-ok" : "b-bad"}`}>{a.outcome}</span></td><td className="mono">{a.source_ip || "—"}</td><td className="sub mono">{Object.keys(a.details).length ? JSON.stringify(a.details) : ""}</td></tr>)}</tbody></table></div>}
          {data && <Pager total={data.total} limit={p.limit} offset={p.offset} onChange={p.setOffset} />}
        </StateView>
      </div>
    </>
  );
}
