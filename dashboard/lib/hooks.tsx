"use client";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, describeError, streamNdjson } from "./api";

export interface Me {
  username: string;
  role: string;
  permissions: string[];
}

const AuthCtx = createContext<{ me: Me; can: (p: string) => boolean } | null>(null);
export const AuthProvider = ({ me, children }: { me: Me; children: ReactNode }) => (
  <AuthCtx.Provider value={{ me, can: (p) => me.permissions.includes(p) }}>{children}</AuthCtx.Provider>
);
export function useAuth() {
  const v = useContext(AuthCtx);
  if (!v) throw new Error("AuthProvider missing");
  return v;
}

export function useApi<T>(path: string | null, opts: { pollMs?: number } = {}) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const load = useCallback(
    async (silent = false) => {
      if (path === null) return;
      const id = ++seq.current;
      if (!silent) setLoading(true);
      try {
        const d = await api<T>(path);
        if (id === seq.current) {
          setData(d);
          setError(null);
        }
      } catch (e) {
        if (id === seq.current) setError(describeError(e));
      } finally {
        if (id === seq.current) setLoading(false);
      }
    },
    [path],
  );
  useEffect(() => {
    void load();
    if (!opts.pollMs) return;
    const t = setInterval(() => void load(true), opts.pollMs);
    return () => clearInterval(t);
  }, [load, opts.pollMs]);
  return { data, error, loading, reload: () => load(), setData };
}

export function useEventStream(onEvent: (e: any) => void) {
  const [state, setState] = useState<"connecting" | "live" | "offline">("connecting");
  const cb = useRef(onEvent);
  cb.current = onEvent;
  useEffect(() => {
    const ac = new AbortController();
    let retry = 1000;
    (async () => {
      while (!ac.signal.aborted) {
        try {
          for await (const msg of streamNdjson("ids/stream", ac.signal)) {
            setState("live");
            retry = 1000;
            if (msg.type === "event") cb.current(msg.event);
          }
        } catch {
          /* fallthrough to reconnect */
        }
        if (ac.signal.aborted) return;
        setState("offline");
        await new Promise((r) => setTimeout(r, retry));
        retry = Math.min(retry * 2, 15000);
      }
    })();
    return () => ac.abort();
  }, []);
  return state;
}

export function usePaging(initial = 25) {
  const [limit, setLimit] = useState(initial);
  const [offset, setOffset] = useState(0);
  return { limit, offset, setLimit, setOffset };
}
