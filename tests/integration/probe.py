#!/usr/bin/env python3
"""Minimal TCP/UDP peer used by the kernel-enforcement tests.

The tests start a server inside the protected namespace and a client inside a
peer namespace, so packets really traverse the veth link and the netfilter hooks.

    python3 probe.py serve  --host 10.10.0.1 --port 9000 --proto tcp
    python3 probe.py client --host 10.10.0.1 --port 9000 --proto tcp --source 10.10.0.2
    python3 probe.py flood  --host 10.10.0.1 --port 9999 --count 80

``client`` exits 0 when the peer answered, 1 when the packet was dropped or
rejected (or the handshake timed out). ``serve`` prints ``READY`` on stdout once
it is bound, then serves until it is terminated.
"""

from __future__ import annotations

import argparse
import socket
import sys


def _family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _socktype(proto: str) -> int:
    return socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM


def serve(args: argparse.Namespace) -> int:
    sock = socket.socket(_family(args.host), _socktype(args.proto))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    if args.proto == "tcp":
        sock.listen(64)
    print("READY", flush=True)
    try:
        while True:
            if args.proto == "tcp":
                conn, _ = sock.accept()
                conn.close()
            else:
                _, peer = sock.recvfrom(2048)
                sock.sendto(b"pong", peer)
    except (KeyboardInterrupt, OSError):
        return 0
    finally:
        sock.close()


def client(args: argparse.Namespace) -> int:
    sock = socket.socket(_family(args.host), _socktype(args.proto))
    sock.settimeout(args.timeout)
    try:
        if args.source:
            sock.bind((args.source, 0))
        if args.proto == "tcp":
            sock.connect((args.host, args.port))
        else:
            sock.sendto(b"ping", (args.host, args.port))
            sock.recvfrom(2048)
    except OSError as exc:
        print(f"unreachable: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        sock.close()
    print("reachable")
    return 0


def flood(args: argparse.Namespace) -> int:
    """Fire ``count`` SYNs from one source address without completing a handshake."""
    family, proto = _family(args.host), _socktype(args.proto)
    for _ in range(args.count):
        sock = socket.socket(family, proto)
        try:
            if args.source:
                sock.bind((args.source, 0))
            sock.setblocking(False)
            sock.connect_ex((args.host, args.port))
        finally:
            sock.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, fn in (("serve", serve), ("client", client), ("flood", flood)):
        p = sub.add_parser(name)
        p.add_argument("--host", required=True)
        p.add_argument("--port", type=int, required=True)
        p.add_argument("--proto", choices=("tcp", "udp"), default="tcp")
        p.add_argument("--source", default=None)
        p.add_argument("--timeout", type=float, default=1.0)
        p.add_argument("--count", type=int, default=80)
        p.set_defaults(func=fn)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
