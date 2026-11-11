"use client";
import { useState } from "react";
import { api, describeError, type Page } from "@/lib/api";
import { useApi, useAuth } from "@/lib/hooks";
import { Badge, Confirm, Header, Notice, StateView } from "@/components/ui";

interface W { network: string; comment: string; source: string }

export default function Whitelist() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi<Page<W>>("whitelist?limit=200");
  const [net, setNet] = useState(""); const [comment, setComment] = useState("");
  const [msg, setMsg] = useState<{ kind: "err" | "okmsg"; text: string } | null>(null);
  const [rm, setRm] = useState<W | null>(null);
  return (
    <>
      <Header title="Whitelist" sub="Always accepted before bans and rate limits; never auto-banned. Adding an entry ends overlapping bans." />
      {msg && <Notice kind={msg.kind} onClose={() => setMsg(null)}>{msg.text}</Notice>}
      {can("whitelist:write") && <div className="card" style={{ marginBottom: 14 }}><div className="row">
        <label>IP or CIDR<input value={net} onChange={(e) => setNet(e.target.value)} placeholder="192.0.2.0/24" /></label>
        <label>Comment<input value={comment} maxLength={100} onChange={(e) => setComment(e.target.value)} /></label>
        <button disabled={!net.trim()} onClick={async () => { try { await api("whitelist", { method: "POST", body: { network: net.trim(), comment } }); setMsg({ kind: "okmsg", text: "Added." }); setNet(""); setComment(""); reload(); } catch (e) { setMsg({ kind: "err", text: describeError(e) }); } }}>Add</button>
      </div></div>}
      <div className="card"><StateView loading={loading} error={error} onRetry={reload} empty={data?.total === 0}>
        {data && <table><thead><tr><th>Network</th><th>Comment</th><th>Origin</th><th /></tr></thead>
          <tbody>{data.items.map((w) => <tr key={w.network}><td className="mono">{w.network}</td><td className="sub">{w.comment}</td><td><Badge kind={w.source === "config" ? "acc" : "ok"}>{w.source}</Badge></td>
            <td>{w.source === "database" && can("whitelist:write") && <button className="danger sm" onClick={() => setRm(w)}>Remove</button>}</td></tr>)}</tbody></table>}
      </StateView></div>
      {rm && <Confirm danger title="Remove from whitelist?" confirmLabel="Remove" message={<>{rm.network} will no longer be exempt from bans and limits.</>} onCancel={() => setRm(null)}
        onConfirm={async () => { try { await api(`whitelist/${rm.network}`, { method: "DELETE" }); reload(); } catch (e) { setMsg({ kind: "err", text: describeError(e) }); } setRm(null); }} />}
    </>
  );
}
