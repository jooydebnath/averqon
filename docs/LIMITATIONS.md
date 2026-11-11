# Limitations (read before relying on Averqon)

**DDoS.** This is host-level filtering. SYN rate limits, connection limits, SYN cookies and bans make single-host floods harder, but they run *after* packets reach your NIC. Volumetric attacks saturate the link before any host firewall can help; you need upstream mitigation (provider scrubbing, anycast/CDN). Per-source limits do nothing against distributed floods from many addresses, and spoofed-source floods can make a ban list useless (reverse-path filtering helps).

**Detection is heuristic.** Port-scan detection only sees packets the firewall *drops and logs* (rate-limited to 10/s), within a 60 s window; slow scans are missed. Brute-force detection depends on log formats; unusual sshd/web log formats need custom filters. Attackers behind shared NAT can cause collateral bans; use `ignore_networks`/whitelist and escalation limits.

**Verification gaps.** Kernel enforcement and the iptables backend are not exercised by tests on a live kernel (see README). Distribution installs were not performed on every supported OS.

**Platform.** Python ≥ 3.12 is required. The iptables backend has no ipset support: blocklists above 2000 entries are rejected (use nftables), and ban expiry is enforced by the daemon, not the kernel. IPv4-mapped IPv6 addresses are normalized to IPv4 in log-derived events, but manual bans of `::ffff:a.b.c.d` are stored as IPv6.

**Scope.** Rate limiting for the API is per process (in-memory); behind multiple API workers use an upstream limiter. Dashboard settings are read-only (configuration lives in the YAML file). Redis-based distributed event processing is not implemented. GeoIP uses user-supplied per-country zone files; no GeoIP database is bundled. There is no HA/cluster mode.

**Persistence.** nftables/iptables state is not persistent across reboot by itself; the executor re-applies the stored policy at start. If the executor fails to start, Averqon's rules are absent (the host's own firewall keeps working).
