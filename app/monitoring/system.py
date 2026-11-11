"""Host metrics (psutil) and Prometheus text exposition."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

import psutil


def system_snapshot() -> dict[str, Any]:
    vm, du = psutil.virtual_memory(), psutil.disk_usage("/")
    load = psutil.getloadavg()
    return {
        "cpu_percent": psutil.cpu_percent(interval=None), "cpu_count": psutil.cpu_count(),
        "load_avg": list(load),
        "memory": {"total": vm.total, "used": vm.used, "percent": vm.percent},
        "disk": {"total": du.total, "used": du.used, "percent": du.percent},
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }


def interface_stats() -> list[dict[str, Any]]:
    io = psutil.net_io_counters(pernic=True)
    stats = psutil.net_if_stats()
    out = []
    for name, c in sorted(io.items()):
        st = stats.get(name)
        out.append({"name": name, "up": bool(st and st.isup), "speed_mbps": st.speed if st else 0,
                    "bytes_sent": c.bytes_sent, "bytes_recv": c.bytes_recv, "packets_sent": c.packets_sent,
                    "packets_recv": c.packets_recv, "errin": c.errin, "errout": c.errout,
                    "dropin": c.dropin, "dropout": c.dropout})
    return out


def connections(limit: int = 500) -> dict[str, Any]:
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return {"items": [], "total": 0, "by_state": {}, "error": "insufficient privileges"}
    items = [{"proto": "tcp" if c.type == 1 else "udp", "family": "ipv6" if c.family.value == 10 else "ipv4",
              "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
              "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
              "state": c.status, "pid": c.pid} for c in conns]
    return {"items": items[:limit], "total": len(items), "by_state": dict(Counter(i["state"] for i in items))}


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def prometheus_text(extra: dict[str, float] | None = None, labelled: dict[str, dict[str, float]] | None = None) -> str:
    """Render Prometheus exposition format. ``labelled`` maps metric -> {label_value: value}."""
    snap = system_snapshot()
    lines: list[str] = []

    def gauge(name: str, value: float, help_: str, labels: str = "") -> None:
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name}{labels} {value}")

    gauge("averqon_cpu_percent", snap["cpu_percent"], "CPU utilisation percent")
    gauge("averqon_memory_percent", snap["memory"]["percent"], "Memory utilisation percent")
    gauge("averqon_disk_percent", snap["disk"]["percent"], "Root disk utilisation percent")
    gauge("averqon_load1", snap["load_avg"][0], "1 minute load average")
    for name, val in sorted((extra or {}).items()):
        gauge(f"averqon_{name}", val, name.replace("_", " "))
    for name, series in sorted((labelled or {}).items()):
        lines.append(f"# HELP averqon_{name} {name.replace('_', ' ')}")
        lines.append(f"# TYPE averqon_{name} gauge")
        for lv, val in sorted(series.items()):
            lines.append(f'averqon_{name}{{label="{_esc(str(lv))}"}} {val}')
    lines.append("# HELP averqon_interface_bytes_total Interface byte counters")
    lines.append("# TYPE averqon_interface_bytes_total counter")
    for i in interface_stats():
        lines.append(f'averqon_interface_bytes_total{{interface="{_esc(i["name"])}",direction="rx"}} {i["bytes_recv"]}')
        lines.append(f'averqon_interface_bytes_total{{interface="{_esc(i["name"])}",direction="tx"}} {i["bytes_sent"]}')
    return "\n".join(lines) + "\n"
