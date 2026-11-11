"use client";
import { useEffect, useRef, useState } from "react";
import { LineChart } from "@/components/charts";
import { Header, StateView, fmtBytes } from "@/components/ui";
import { useApi } from "@/lib/hooks";

interface If { name: string; up: boolean; speed_mbps: number; bytes_sent: number; bytes_recv: number; packets_sent: number; packets_recv: number; errin: number; errout: number; dropin: number; dropout: number }
const N = 60;

export default function Network() {
  const { data, error, loading, reload } = useApi<If[]>("network/interfaces", { pollMs: 3000 });
  const prev = useRef<{ t: number; v: Record<string, If> } | null>(null);
  const [hist, setHist] = useState<Record<string, { rx: number[]; tx: number[] }>>({});
  useEffect(() => {
    if (!data) return;
    const now = Date.now();
    const cur = Object.fromEntries(data.map((i) => [i.name, i]));
    if (prev.current) {
      const dt = (now - prev.current.t) / 1000;
      if (dt > 0.5) setHist((h) => { const n = { ...h }; for (const i of data) { const p = prev.current!.v[i.name]; if (!p) continue; const e = n[i.name] ?? { rx: [], tx: [] }; n[i.name] = { rx: [...e.rx, Math.max(0, (i.bytes_recv - p.bytes_recv) / dt / 1024)].slice(-N), tx: [...e.tx, Math.max(0, (i.bytes_sent - p.bytes_sent) / dt / 1024)].slice(-N) }; } return n; });
    }
    prev.current = { t: now, v: cur };
  }, [data]);
  return (
    <>
      <Header title="Network monitoring" sub="Throughput is computed from live kernel counters (KiB/s), sampled every 3 seconds." />
      <StateView loading={loading} error={error} onRetry={reload} empty={data?.length === 0}>
        <div className="grid g2">{data?.map((i) => (
          <div className="card" key={i.name}>
            <h2>{i.name} <span className={`badge ${i.up ? "b-ok" : "b-bad"}`}>{i.up ? "up" : "down"}</span> {i.speed_mbps > 0 && <span className="sub">{i.speed_mbps} Mb/s</span>}</h2>
            <LineChart unit=" KiB/s" series={[{ name: "rx", points: hist[i.name]?.rx ?? [] }, { name: "tx", points: hist[i.name]?.tx ?? [] }]} />
            <div className="sub" style={{ marginTop: 8 }}>RX {fmtBytes(i.bytes_recv)} ({i.packets_recv.toLocaleString()} pkts) · TX {fmtBytes(i.bytes_sent)} ({i.packets_sent.toLocaleString()} pkts) · errors {i.errin + i.errout} · drops {i.dropin + i.dropout}</div>
          </div>))}</div>
      </StateView>
    </>
  );
}
