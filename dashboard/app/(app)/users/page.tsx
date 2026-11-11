"use client";
import { useState } from "react";
import { api, describeError, type Page } from "@/lib/api";
import { useApi, useAuth } from "@/lib/hooks";
import { Confirm, Header, Notice, StateView, fmtTime } from "@/components/ui";

interface U { id: number; username: string; role: string; enabled: boolean; last_login: string | null; locked: boolean }
const ROLES = ["viewer", "auditor", "operator", "admin"];

export default function Users() {
  const { me } = useAuth();
  const { data, error, loading, reload } = useApi<Page<U>>("users?limit=200");
  const [f, setF] = useState({ username: "", password: "", role: "viewer" });
  const [msg, setMsg] = useState<{ kind: "err" | "okmsg"; text: string } | null>(null);
  const [del, setDel] = useState<U | null>(null);
  const [pw, setPw] = useState<{ u: U; value: string } | null>(null);
  const act = async (fn: () => Promise<unknown>, ok: string) => { try { await fn(); setMsg({ kind: "okmsg", text: ok }); reload(); } catch (e) { setMsg({ kind: "err", text: describeError(e) }); } };
  return (
    <>
      <Header title="Users & roles" sub="viewer: read-only · auditor: + audit logs · operator: + rules, bans, whitelist · admin: everything" />
      {msg && <Notice kind={msg.kind} onClose={() => setMsg(null)}>{msg.text}</Notice>}
      <div className="card" style={{ marginBottom: 14 }}><h2>New user</h2><div className="row">
        <label>Username<input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} autoComplete="off" /></label>
        <label>Password (min 12)<input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" /></label>
        <label>Role<select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select></label>
        <button disabled={!f.username || f.password.length < 12} onClick={() => act(async () => { await api("users", { method: "POST", body: f }); setF({ username: "", password: "", role: "viewer" }); }, "User created.")}>Create</button>
      </div></div>
      <div className="card"><StateView loading={loading} error={error} onRetry={reload} empty={data?.total === 0}>
        {data && <div className="tw"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last login</th><th /></tr></thead>
          <tbody>{data.items.map((u) => <tr key={u.id}><td>{u.username}{u.id && u.username === me.username ? " (you)" : ""}</td>
            <td><select value={u.role} onChange={(e) => act(() => api(`users/${u.id}`, { method: "PATCH", body: { role: e.target.value } }), "Role updated; the user's sessions were revoked.")}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select></td>
            <td>{u.locked ? <span className="badge b-bad">locked</span> : u.enabled ? <span className="badge b-ok">enabled</span> : <span className="badge">disabled</span>}</td><td className="sub">{fmtTime(u.last_login)}</td>
            <td style={{ whiteSpace: "nowrap" }}><button className="sec sm" onClick={() => act(() => api(`users/${u.id}`, { method: "PATCH", body: { enabled: !u.enabled } }), u.enabled ? "User disabled." : "User enabled.")}>{u.enabled ? "Disable" : "Enable"}</button>{" "}
              <button className="sec sm" onClick={() => setPw({ u, value: "" })}>Reset password</button>{" "}<button className="danger sm" onClick={() => setDel(u)}>Delete</button></td></tr>)}</tbody></table></div>}
      </StateView></div>
      {del && <Confirm danger title="Delete user?" confirmLabel="Delete" message={<>{del.username} will lose access immediately.</>} onCancel={() => setDel(null)} onConfirm={async () => { await act(() => api(`users/${del.id}`, { method: "DELETE" }), "User deleted."); setDel(null); }} />}
      {pw && <div className="modal" onClick={() => setPw(null)}><div className="dlg" onClick={(e) => e.stopPropagation()}><h2>Reset password for {pw.u.username}</h2>
        <label>New password (min 12)<input type="password" value={pw.value} onChange={(e) => setPw({ ...pw, value: e.target.value })} autoComplete="new-password" /></label>
        <div className="row"><button className="sec" onClick={() => setPw(null)}>Cancel</button><button disabled={pw.value.length < 12} onClick={async () => { await act(() => api(`users/${pw.u.id}`, { method: "PATCH", body: { password: pw.value } }), "Password updated; sessions revoked."); setPw(null); }}>Update</button></div></div></div>}
    </>
  );
}
