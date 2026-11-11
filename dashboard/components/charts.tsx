"use client";
const COLORS = ["#4f8cff", "#2fbf71", "#e0a526", "#e5484d", "#b4308b", "#8b97b3"];

export function BarChart({ data, height = 160, colors }: { data: { label: string; value: number }[]; height?: number; colors?: Record<string, string> }) {
  const max = Math.max(1, ...data.map((d) => d.value));
  if (data.length === 0) return <div className="state">No data in this period.</div>;
  const w = 100 / data.length;
  return (
    <svg viewBox={`0 0 ${data.length * 60} ${height}`} width="100%" role="img" aria-label="bar chart">
      {data.map((d, i) => {
        const h = (d.value / max) * (height - 40);
        return (
          <g key={d.label} transform={`translate(${i * 60 + 8},0)`}>
            <rect y={height - 24 - h} width={44} height={h} rx={4} fill={colors?.[d.label] ?? COLORS[i % COLORS.length]}><title>{`${d.label}: ${d.value}`}</title></rect>
            <text x={22} y={height - 28 - h} textAnchor="middle" fill="#e6ebf5" fontSize="11">{d.value}</text>
            <text x={22} y={height - 8} textAnchor="middle" fill="#8b97b3" fontSize="10">{d.label.length > 9 ? d.label.slice(0, 8) + "…" : d.label}</text>
          </g>
        );
      })}
      <title>{`bars ${w}`}</title>
    </svg>
  );
}

export function LineChart({ series, height = 140, unit = "" }: { series: { name: string; color?: string; points: number[] }[]; height?: number; unit?: string }) {
  const n = Math.max(...series.map((s) => s.points.length), 0);
  const max = Math.max(1, ...series.flatMap((s) => s.points));
  if (n < 2) return <div className="state">Collecting samples…</div>;
  const W = 400;
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${height}`} width="100%" role="img" aria-label="line chart">
        {[0.25, 0.5, 0.75].map((f) => <line key={f} x1={0} x2={W} y1={height * f} y2={height * f} stroke="#243049" strokeDasharray="3 4" />)}
        {series.map((s, si) => (
          <polyline key={s.name} fill="none" stroke={s.color ?? COLORS[si]} strokeWidth={2}
            points={s.points.map((p, i) => `${(i / (n - 1)) * W},${height - 4 - (p / max) * (height - 12)}`).join(" ")} />
        ))}
      </svg>
      <div className="row sub" style={{ justifyContent: "space-between" }}>
        <span>{series.map((s, i) => <span key={s.name} style={{ color: s.color ?? COLORS[i], marginRight: 12 }}>● {s.name}</span>)}</span>
        <span>peak {max.toFixed(1)}{unit}</span>
      </div>
    </div>
  );
}

export const Meter = ({ percent }: { percent: number }) => (
  <div className="bar" role="progressbar" aria-valuenow={Math.round(percent)} aria-valuemin={0} aria-valuemax={100}>
    <i style={{ width: `${Math.min(100, percent)}%`, background: percent > 90 ? "var(--bad)" : percent > 75 ? "var(--warn)" : "var(--acc)" }} />
  </div>
);
