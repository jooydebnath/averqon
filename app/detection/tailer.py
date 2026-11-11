"""Async log sources: file tailer (rotation-safe) and journald follower."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path

log = logging.getLogger(__name__)


async def tail_file(path: Path, *, poll: float = 0.5, from_start: bool = False,
                    stop: asyncio.Event | None = None) -> AsyncIterator[str]:
    """Yield new lines appended to ``path``; survives rotation (inode change) and truncation."""
    fh = None
    inode = -1
    try:
        while stop is None or not stop.is_set():
            try:
                st = os.stat(path)
            except FileNotFoundError:
                if fh:
                    fh.close()
                    fh, inode = None, -1
                await asyncio.sleep(poll)
                continue
            if fh is None or st.st_ino != inode:
                if fh:
                    fh.close()
                fh = open(path, encoding="utf-8", errors="replace")  # noqa: SIM115, ASYNC230
                if not (from_start or inode != -1):
                    fh.seek(0, os.SEEK_END)
                inode = st.st_ino
            elif st.st_size < fh.tell():  # truncated
                fh.seek(0)
            line = fh.readline()
            if line:
                if line.endswith("\n"):
                    yield line.rstrip("\n")
                else:  # partial write: wait for the rest
                    fh.seek(fh.tell() - len(line.encode("utf-8", "replace")))
                    await asyncio.sleep(poll)
            else:
                await asyncio.sleep(poll)
    finally:
        if fh:
            fh.close()


async def follow_journal(units: list[str], *, kernel: bool = False, journalctl: str = "journalctl",
                         stop: asyncio.Event | None = None) -> AsyncIterator[str]:
    """Follow systemd journal output. Arguments are a fixed argv (no shell); units are pre-validated."""
    argv = [journalctl, "-f", "-n", "0", "-o", "cat", "--no-pager"]
    argv += ["-k"] if kernel else [a for u in units for a in ("-u", u)]
    proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.DEVNULL)
    try:
        assert proc.stdout is not None
        while stop is None or not stop.is_set():
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), 1.0)
            except TimeoutError:
                continue
            if not raw:
                break
            yield raw.decode("utf-8", "replace").rstrip("\n")
    finally:
        if proc.returncode is None:
            proc.terminate()
            await proc.wait()
