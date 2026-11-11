"use client";
import { useState } from "react";
import { api, describeError, type Page } from "@/lib/api";
import { useApi, useAuth, usePaging } from "@/lib/hooks";
import { Badge, Confirm, Header, Notice, Pager, StateView } from "@/components/ui";

interface Rule { id: number; name: string; enabled: boolean; priority: number; direction: string; action: string; protocol: string; source: string | null; destination: string | null; dport: string[]; sport: string[]; interface: string | null; states: string[]; rate_limit: string | null; log: boolean; group: string | null; comment: string }
const BLANK = { name: "", priority: "1000", direction: "in", action: "drop", protocol: "tcp", source: "", destination: "", dport: "", interface: "", rate_limit: "", comment: "", log: false, enabled: true };

export default function Rules() {
  const { can } = useAuth();
  const p = usePaging(25);
  const { data, error, loading, reload } = useApi<Page<Rule>>(`firewall/rules?limit=${p.limit}&offset=${p.offset}`);
  const [form, setForm] = useState<typeof BLANK | null>(null);
  const [editId, setEditId] = useState<number | null>(null);
  const [force, setForce] = useState(false);
  const [msg, setMsg] = useState<{ kind: "err" | "okmsg"; text: string } | null>(null);
  const [del, setDel] = useState<Rule | null>(null);
  const [busy, setBusy] = useState(false);

  const toBody = (f: typeof BLANK) => ({
    name: f.name || "rule", priority: Number(f.priority), direction: f.direction, action: f.action, protocol: f.protocol,
    source: f.source || null, destination: f.destination || null, interface: f.interface || null, rate_limit: f.rate_limit || null,
    dport: f.dport.split(",").map((s) => s.trim()).filter(Boolean), comment: f.comment, log: f.log, enabled: f.enabled,
  });
  async function save(dry: boolean) {
    if (!form) return;
    setBusy(true); setMsg(null);
    try {
      const q = `?force=${force}${dry && editId === null ? "&dry_run=true" : ""}`;
      if (editId === null) await api("firewall/rules" + q, { method: "POST", body: toBody(form) });
      else await api(`firewall/rules/${editId}${q}`, { method: "PUT", body: toBody(form) });
      setMsg({ kind: "okmsg", text: dry && editId === null ? "Dry run OK: the rule is valid and would apply cleanly." : "Rule saved and applied." });
      if (!dry || editId !== null) { setForm(null); setEditId(null); reload(); }
    } catch (e) { setMsg({ kind: "err", text: describeError(e) }); } finally { setBusy(false); }
  }
  const edit = (r: Rule) => { setEditId(r.id); setForm({ name: r.name, priority: String(r.priority), direction: r.direction, action: r.action, protocol: r.protocol, source: r.source ?? "", destination: r.destination ?? "", dport: r.dport.join(","), interface: r.interface ?? "", rate_limit: r.rate_limit ?? "", comment: r.comment, log: r.log, enabled: r.enabled }); setMsg(null); };
  const set = (k: keyof typeof BLANK, v: string | boolean) => setForm((f) => (f ? { ...f, [k]: v } : f));

  return (
    <>
      <Header title="Firewall rules" sub="Evaluated by priority (lower first). Changes are validated, applied atomically, and rolled back on failure."
        actions={can("rules:write") && <button onClick={() => { setForm({ ...BLANK }); setEditId(null); setMsg(null); }}>Add rule</button>} />
      {msg && <Notice kind={msg.kind} onClose={() => setMsg(null)}>{msg.text}</Notice>}
      {form && (
        <div className="card" style={{ marginBottom: 14 }}>
          <h2>{editId === null ? "New rule" : `Edit rule #${editId}`}</h2>
          <div className="form">
            <label>Name<input value={form.name} onChange={(e) => set("name", e.target.value)} maxLength={64} /></label>
            <label>Priority (0–9999)<input type="number" min={0} max={9999} value={form.priority} onChange={(e) => set("priority", e.target.value)} /></label>
            <label>Direction<select value={form.direction} onChange={(e) => set("direction", e.target.value)}><option>in</option><option>out</option></select></label>
            <label>Action<select value={form.action} onChange={(e) => set("action", e.target.value)}><option>accept</option><option>drop</option><option>reject</option></select></label>
            <label>Protocol<select value={form.protocol} onChange={(e) => set("protocol", e.target.value)}>{["any", "tcp", "udp", "icmp", "icmpv6"].map((x) => <option key={x}>{x}</option>)}</select></label>
            <label>Source (IP/CIDR)<input value={form.source} onChange={(e) => set("source", e.target.value)} placeholder="any" /></label>
            <label>Destination (IP/CIDR)<input value={form.destination} onChange={(e) => set("destination", e.target.value)} placeholder="any" /></label>
            <label>Dest. ports (comma, ranges ok)<input value={form.dport} onChange={(e) => set("dport", e.target.value)} placeholder="80, 443, 8000-8100" /></label>
            <label>Interface<input value={form.interface} onChange={(e) => set("interface", e.target.value)} placeholder="any" /></label>
            <label>Rate limit<input value={form.rate_limit} onChange={(e) => set("rate_limit", e.target.value)} placeholder="10/second" /></label>
            <label>Comment<input value={form.comment} onChange={(e) => set("comment", e.target.value)} maxLength={100} /></label>
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <label style={{ flexDirection: "row", alignItems: "center" }}><input type="checkbox" checked={form.log} onChange={(e) => set("log", e.target.checked)} /> log matches</label>
            <label style={{ flexDirection: "row", alignItems: "center" }}><input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} /> enabled</label>
            <label style={{ flexDirection: "row", alignItems: "center" }}><input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} /> allow conflicts</label>
            <span style={{ flex: 1 }} />
            <button className="sec" onClick={() => { setForm(null); setEditId(null); }}>Cancel</button>
            {editId === null && <button className="sec" disabled={busy} onClick={() => save(true)}>Dry run</button>}
            <button disabled={busy} onClick={() => save(false)}>{busy ? "Applying…" : "Save & apply"}</button>
          </div>
        </div>
      )}
      <div className="card">
        <StateView loading={loading} error={error} onRetry={reload} empty={data?.total === 0}>
          {data && <div className="tw"><table>
            <thead><tr><th>Pri</th><th>Name</th><th>Dir</th><th>Action</th><th>Proto</th><th>Source → Destination</th><th>Ports</th><th>Notes</th><th /></tr></thead>
            <tbody>{data.items.map((r) => (
              <tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.5 }}>
                <td>{r.priority}</td><td>{r.name}</td><td>{r.direction}</td>
                <td><Badge kind={r.action === "accept" ? "ok" : "bad"}>{r.action}</Badge></td><td>{r.protocol}</td>
                <td className="mono">{r.source ?? "*"} → {r.destination ?? "*"}{r.interface ? ` @${r.interface}` : ""}</td>
                <td className="mono">{r.dport.join(", ") || "*"}</td>
                <td className="sub">{[r.rate_limit && `limit ${r.rate_limit}`, r.log && "log", r.comment].filter(Boolean).join(" · ")}</td>
                <td style={{ whiteSpace: "nowrap" }}>{can("rules:write") && <><button className="sec sm" onClick={() => edit(r)}>Edit</button> <button className="danger sm" onClick={() => setDel(r)}>Delete</button></>}</td>
              </tr>))}</tbody></table></div>}
          {data && <Pager total={data.total} limit={p.limit} offset={p.offset} onChange={p.setOffset} />}
        </StateView>
      </div>
      {del && <Confirm danger title="Delete rule?" confirmLabel="Delete" message={<>Rule <b>{del.name}</b> (#{del.id}) will be removed and the ruleset re-applied.</>} onCancel={() => setDel(null)}
        onConfirm={async () => { try { await api(`firewall/rules/${del.id}`, { method: "DELETE" }); setMsg({ kind: "okmsg", text: "Rule deleted." }); reload(); } catch (e) { setMsg({ kind: "err", text: describeError(e) }); } setDel(null); }} />}
    </>
  );
}
