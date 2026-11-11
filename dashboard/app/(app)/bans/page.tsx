"use client";
import { useState } from "react";
import { api, describeError, type Page } from "@/lib/api";
import { useApi, useAuth, usePaging } from "@/lib/hooks";
import { Confirm, Header, Notice, Pager, StateView, fmtTime } from "@/components/ui";

interface Ban { id: number; network: string; reason: string; source: string; actor: string; created_at: string; expires_at: string | null; active: boolean; ended_by: string }

export default function Bans() {
  const { can } = useAuth();
  const p = usePaging(25);
  const [all, setAll] = useState(false);
  const { data, error, loading, reload } = useApi<Page<Ban>>(`ips/bans?limit=${p.limit}&offset=${p.offset}&active_only=${!all}`, { pollMs: 15000 });
  const [net, setNet] = useState(""); const [ttl, setTtl] = useState("3600"); const [reason, setReason] = useState("");
  const [msg, setMsg] = useState<{ kind: "err" | "okmsg"; text: string } | null>(null);
  const [un, setUn] = useState<Ban | null>(null);
  const [confirmBan, setConfirmBan] = useState(false);

  async function ban() {
    try {
      await api("ips/ban", { method: "POST", body: { network: net.trim(), ttl_seconds: ttl === "" ? null : Number(ttl), reason } });
      setMsg({ kind: "okmsg", text: `Banned ${net}.` }); setNet(""); setReason(""); reload();
    } catch (e) { setMsg({ kind: "err", text: describeError(e) }); }
    setConfirmBan(false);
  }
  return (
    <>
      <Header title="Banned IP addresses" sub="Whitelisted addresses and the management host can never be banned." />
      {msg && <Notice kind={msg.kind} onClose={() => setMsg(null)}>{msg.text}</Notice>}
      {can("bans:write") && <div className="card" style={{ marginBottom: 14 }}><h2>Manual ban</h2>
        <div className="row">
          <label>IP or CIDR<input value={net} onChange={(e) => setNet(e.target.value)} placeholder="203.0.113.5 or 198.51.100.0/24" /></label>
          <label>Duration (seconds, blank = permanent)<input type="number" min={1} value={ttl} onChange={(e) => setTtl(e.target.value)} /></label>
          <label>Reason<input value={reason} maxLength={200} onChange={(e) => setReason(e.target.value)} /></label>
          <button disabled={!net.trim()} onClick={() => setConfirmBan(true)}>Ban</button>
        </div></div>}
      <div className="card">
        <label style={{ flexDirection: "row", alignItems: "center", marginBottom: 10 }}><input type="checkbox" checked={all} onChange={(e) => { setAll(e.target.checked); p.setOffset(0); }} /> include history (expired / removed)</label>
        <StateView loading={loading} error={error} onRetry={reload} empty={data?.total === 0}>
          {data && <div className="tw"><table><thead><tr><th>Network</th><th>Reason</th><th>Source</th><th>Banned</th><th>Expires</th><th>Status</th><th /></tr></thead>
            <tbody>{data.items.map((b) => <tr key={b.id}><td className="mono">{b.network}</td><td className="sub">{b.reason || "—"}</td><td>{b.source}{b.actor ? ` (${b.actor})` : ""}</td><td className="sub">{fmtTime(b.created_at)}</td><td className="sub">{b.expires_at ? fmtTime(b.expires_at) : "never"}</td>
              <td>{b.active ? <span className="badge b-bad">active</span> : <span className="badge">ended{b.ended_by ? ` (${b.ended_by})` : ""}</span>}</td>
              <td>{b.active && can("bans:write") && <button className="sec sm" onClick={() => setUn(b)}>Unban</button>}</td></tr>)}</tbody></table></div>}
          {data && <Pager total={data.total} limit={p.limit} offset={p.offset} onChange={p.setOffset} />}
        </StateView>
      </div>
      {confirmBan && <Confirm danger title="Ban this address?" confirmLabel="Ban" message={<>Traffic from <b>{net}</b> will be dropped{ttl ? ` for ${ttl}s` : " permanently"}.</>} onCancel={() => setConfirmBan(false)} onConfirm={ban} />}
      {un && <Confirm title="Remove ban?" confirmLabel="Unban" message={<>{un.network} will be able to connect again.</>} onCancel={() => setUn(null)}
        onConfirm={async () => { try { await api("ips/unban", { method: "POST", body: { network: un.network } }); setMsg({ kind: "okmsg", text: `Unbanned ${un.network}.` }); reload(); } catch (e) { setMsg({ kind: "err", text: describeError(e) }); } setUn(null); }} />}
    </>
  );
}
