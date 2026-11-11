"use client";
import { useState } from "react";
import { BarChart } from "@/components/charts";
import { Header, StateView } from "@/components/ui";
import { useApi } from "@/lib/hooks";

interface Stats { hours: number; by_severity: Record<string, number>; by_kind: Record<string, number>; top_sources: { ip: string; count: number }[] }

export default function Analytics() {
  const [hours, setHours] = useState(24);
  const { data, error, loading, reload } = useApi<Stats>(`ids/stats?hours=${hours}`, { pollMs: 30000 });
  const total = data ? Object.values(data.by_kind).reduce((a, b) => a + b, 0) : 0;
  return (
    <>
      <Header title="Security analytics" sub="Aggregated from recorded detections" actions={
        <label>Period<select value={hours} onChange={(e) => setHours(Number(e.target.value))}>{[[1, "1 hour"], [24, "24 hours"], [168, "7 days"], [720, "30 days"]].map(([h, l]) => <option key={h} value={h}>{l}</option>)}</select></label>} />
      <StateView loading={loading} error={error} onRetry={reload}>
        {data && (total === 0 ? <div className="card state">No events in this period.</div> : (
          <div className="grid g2">
            <div className="card"><h2>By severity</h2><BarChart data={["low", "medium", "high", "critical"].map((s) => ({ label: s, value: data.by_severity[s] ?? 0 }))} colors={{ low: "#8b97b3", medium: "#e0a526", high: "#e5484d", critical: "#b4308b" }} /></div>
            <div className="card"><h2>By detection type</h2><BarChart data={Object.entries(data.by_kind).map(([label, value]) => ({ label, value }))} /></div>
            <div className="card" style={{ gridColumn: "1 / -1" }}><h2>Top offending sources</h2>
              <table><thead><tr><th>Address</th><th>Events</th><th>Share</th></tr></thead><tbody>{data.top_sources.map((s) => <tr key={s.ip}><td className="mono">{s.ip}</td><td>{s.count}</td><td style={{ width: "50%" }}><div className="bar"><i style={{ width: `${(s.count / total) * 100}%` }} /></div></td></tr>)}</tbody></table></div>
          </div>))}
      </StateView>
    </>
  );
}
