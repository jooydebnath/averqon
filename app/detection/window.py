"""Bounded sliding-window counter keyed by arbitrary strings."""

from __future__ import annotations

from collections import OrderedDict, deque


class SlidingWindow:
    """Counts timestamps per key within ``window`` seconds. Memory-bounded (LRU on keys)."""

    def __init__(self, window: float, max_keys: int = 100_000) -> None:
        self.window, self.max_keys = window, max_keys
        self._d: OrderedDict[str, deque[tuple[float, object]]] = OrderedDict()

    def add(self, key: str, now: float, item: object = None) -> int:
        q = self._d.get(key)
        if q is None:
            q = self._d[key] = deque()
            if len(self._d) > self.max_keys:
                self._d.popitem(last=False)
        else:
            self._d.move_to_end(key)
        q.append((now, item))
        self._trim(q, now)
        return len(q)

    def items(self, key: str, now: float) -> list[object]:
        q = self._d.get(key)
        if q is None:
            return []
        self._trim(q, now)
        return [i for _, i in q]

    def reset(self, key: str) -> None:
        self._d.pop(key, None)

    def _trim(self, q: deque, now: float) -> None:
        cutoff = now - self.window
        while q and q[0][0] <= cutoff:
            q.popleft()

    def purge(self, now: float) -> None:
        for k in [k for k, q in self._d.items() if not q or q[-1][0] <= now - self.window]:
            del self._d[k]

    def __len__(self) -> int:
        return len(self._d)
