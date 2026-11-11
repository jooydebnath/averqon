"use client";
import { useEffect, useState, type ReactNode } from "react";

export const Spinner = () => <span className="spin" aria-label="loading" />;

export function StateView({ loading, error, empty, children, onRetry }: { loading: boolean; error: string | null; empty?: boolean; children: ReactNode; onRetry?: () => void }) {
  if (loading && !children) return <div className="state"><Spinner />Loading…</div>;
  if (error) return <div className="err" role="alert">{error}{onRetry && <> <button className="sm sec" onClick={onRetry}>Retry</button></>}</div>;
  if (empty) return <div className="state">Nothing to show yet.</div>;
  return <>{children}</>;
}

export const Badge = ({ kind, children }: { kind: string; children: ReactNode }) => <span className={`badge b-${kind}`}>{children}</span>;
export const Sev = ({ s }: { s: string }) => <Badge kind={s}>{s}</Badge>;

export const Stat = ({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) => (
  <div className="card stat"><div className="l">{label}</div><div className="v">{value}</div>{hint && <div className="sub">{hint}</div>}</div>
);

export function Pager({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (o: number) => void }) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="pager">
      <span>{total === 0 ? "0 results" : `${offset + 1}–${Math.min(offset + limit, total)} of ${total}`}</span>
      <button className="sec sm" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Prev</button>
      <span>{page} / {pages}</span>
      <button className="sec sm" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</button>
    </div>
  );
}

export function Confirm({ title, message, confirmLabel = "Confirm", danger, onConfirm, onCancel }: { title: string; message: ReactNode; confirmLabel?: string; danger?: boolean; onConfirm: () => void | Promise<void>; onCancel: () => void }) {
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onCancel();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onCancel]);
  return (
    <div className="modal" role="dialog" aria-modal="true" aria-label={title} onClick={onCancel}>
      <div className="dlg" onClick={(e) => e.stopPropagation()}>
        <h2>{title}</h2><div className="sub">{message}</div>
        <div className="row">
          <button className="sec" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className={danger ? "danger" : ""} disabled={busy} onClick={async () => { setBusy(true); try { await onConfirm(); } finally { setBusy(false); } }}>{busy ? "Working…" : confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

export function Notice({ kind, children, onClose }: { kind: "err" | "okmsg"; children: ReactNode; onClose?: () => void }) {
  return <div className={kind} role={kind === "err" ? "alert" : "status"}>{children}{onClose && <button className="sm sec" style={{ float: "right" }} onClick={onClose}>×</button>}</div>;
}

export const Header = ({ title, sub, actions }: { title: string; sub?: string; actions?: ReactNode }) => (
  <div className="top"><div><h1>{title}</h1>{sub && <div className="sub">{sub}</div>}</div><div className="row">{actions}</div></div>
);

export const fmtTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
export const fmtBytes = (n: number) => { const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = n; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return `${v.toFixed(i ? 1 : 0)} ${u[i]}`; };
