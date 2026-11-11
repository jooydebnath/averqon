export class ApiError extends Error {
  constructor(public status: number, message: string, public fields?: { loc: string[]; msg: string }[], public retryAfter?: number) {
    super(message);
  }
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export async function api<T>(path: string, init: { method?: string; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const res = await fetch(`/api/proxy/${path.replace(/^\//, "")}`, {
    method: init.method ?? "GET",
    headers: { "x-averqon-csrf": "1", ...(init.body !== undefined ? { "content-type": "application/json" } : {}) },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    credentials: "same-origin",
    cache: "no-store",
    signal: init.signal,
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON error body */
  }
  if (!res.ok) {
    if (res.status === 401 && typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login";
    }
    const e = data?.error;
    throw new ApiError(res.status, e?.message ?? `Request failed (${res.status})`, e?.fields, Number(res.headers.get("retry-after")) || undefined);
  }
  return data as T;
}

export function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    const f = e.fields?.map((x) => `${x.loc.filter((l) => l !== "body").join(".")}: ${x.msg}`).join("; ");
    return f ? `${e.message} (${f})` : e.message;
  }
  return e instanceof Error ? e.message : "Unknown error";
}

export async function* streamNdjson(path: string, signal: AbortSignal): AsyncGenerator<any> {
  const res = await fetch(`/api/proxy/${path}`, { headers: { "x-averqon-csrf": "1" }, signal, cache: "no-store" });
  if (!res.ok || !res.body) throw new ApiError(res.status, "Stream failed");
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return;
    buf += dec.decode(value, { stream: true });
    let i: number;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) yield JSON.parse(line);
    }
  }
}
