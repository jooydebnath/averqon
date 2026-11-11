"use client";
import { useState } from "react";
import { api, describeError } from "@/lib/api";
import { useApi, useAuth } from "@/lib/hooks";
import { Confirm, Header, Notice, StateView } from "@/components/ui";

interface Settings { environment: string; log_level: string; firewall: Record<string, unknown>; ids: Record<string, unknown>; api: Record<string, unknown>; note: string }
interface Sysctl { key: string; current: string | null; desired: string; needs_change: boolean }

export default function SettingsPage() {
  const { can } = useAuth();
  const s = useApi<Settings>("settings");
  const h = useApi<Sysctl[]>("system/hardening");
  const [msg, setMsg] = useState<{ kind: "err" | "okmsg"; text: string } | null>(null);
  const [ask, setAsk] = useState<null | "harden" | "refresh" | "apply">(null);
  const [dry, setDry] = useState<string | null>(null);

  async function run(kind: "harden" | "refresh" | "apply") {
    try {
      if (kind === "harden") { const r = await api<{ changed: string[] }>("system/hardening/apply", { method: "POST" }); setMsg({ kind: "okmsg", text: `Applied ${r.changed.length} kernel setting(s).` }); h.reload(); }
      if (kind === "refresh") { const r = await api<{ counts: Record<string, number> }>("system/blocklists/refresh", { method: "POST" }); setMsg({ kind: "okmsg", text: `Blocklists refreshed: ${JSON.stringify(r.counts)}` }); }
      if (kind === "apply") { await api("firewall/apply", { method: "POST" }); setMsg({ kind: "okmsg", text: "Ruleset re-applied." }); }
    } catch (e) { setMsg({ kind: "err", text: describeError(e) }); }
    setAsk(null);
  }
  async function preview() {
    try { const r = await api<{ ruleset: string; conflicts: string[] }>("firewall/apply?dry_run=true", { method: "POST" }); setDry(r.ruleset + (r.conflicts.length ? `\n# conflicts:\n${r.conflicts.join("\n")}` : "")); } catch (e) { setMsg({ kind: "err", text: describeError(e) }); }
  }
  return (
    <>
      <Header title="System settings" sub={s.data?.note} />
      {msg && <Notice kind={msg.kind} onClose={() => setMsg(null)}>{msg.text}</Notice>}
      <div className="grid g2">
        <div className="card"><h2>Actions</h2><div className="row">
          {can("firewall:apply") && <><button className="sec" onClick={preview}>Preview ruleset (dry run)</button><button onClick={() => setAsk("apply")}>Re-apply ruleset</button></>}
          {can("settings:write") && <button className="sec" onClick={() => setAsk("refresh")}>Refresh blocklists</button>}
        </div></div>
        <div className="card"><h2>Kernel hardening</h2>
          <StateView loading={h.loading} error={h.error} onRetry={h.reload}>
            <table><tbody>{h.data?.map((c) => <tr key={c.key}><td className="mono">{c.key}</td><td>{c.current ?? "n/a"}</td><td>{c.needs_change && c.current !== null ? <span className="badge b-bad">want {c.desired}</span> : <span className="badge b-ok">ok</span>}</td></tr>)}</tbody></table>
            {can("settings:write") && h.data?.some((c) => c.needs_change && c.current !== null) && <button style={{ marginTop: 10 }} onClick={() => setAsk("harden")}>Apply hardening</button>}
          </StateView></div>
      </div>
      <div className="card" style={{ marginTop: 14 }}><h2>Effective configuration (secrets are never shown)</h2>
        <StateView loading={s.loading} error={s.error} onRetry={s.reload}><pre className="mono" style={{ margin: 0, overflow: "auto" }}>{JSON.stringify(s.data && { environment: s.data.environment, log_level: s.data.log_level, firewall: s.data.firewall, ids: s.data.ids, api: s.data.api }, null, 2)}</pre></StateView></div>
      {dry && <div className="modal" onClick={() => setDry(null)}><div className="dlg" style={{ maxWidth: 800 }} onClick={(e) => e.stopPropagation()}><h2>Ruleset that would be applied</h2><pre className="mono" style={{ maxHeight: "60vh", overflow: "auto" }}>{dry}</pre><div className="row"><button onClick={() => setDry(null)}>Close</button></div></div></div>}
      {ask && <Confirm title={{ harden: "Apply kernel hardening?", refresh: "Refresh blocklists?", apply: "Re-apply the ruleset?" }[ask]} message={{ harden: "Sets the listed sysctl values on the running kernel.", refresh: "Downloads configured feeds and re-applies the ruleset.", apply: "Rebuilds the Averqon table atomically with connectivity rollback." }[ask]} onCancel={() => setAsk(null)} onConfirm={() => run(ask)} />}
    </>
  );
}
