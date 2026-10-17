"""Nonce replay locks: an authorization is presented at most once."""
from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Callable


class MemoryNonceLock:
    """Process-local lock with expiry. Fine for one worker process."""

    def __init__(self, ttl: float = 900, clock: Callable[[], float] = time.time):
        self.ttl = ttl
        self._clock = clock
        self._seen: dict[str, float] = {}
        self._mu = threading.Lock()

    def acquire(self, key: str) -> bool:
        now = self._clock()
        with self._mu:
            if len(self._seen) > 10000:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
            if self._seen.get(key, 0) > now:
                return False
            self._seen[key] = now + self.ttl
            return True

    def release(self, key: str) -> None:
        with self._mu:
            self._seen.pop(key, None)


class FileNonceLock:
    """Lock shared by every worker process on one host, no Redis needed.

    One file per nonce, created atomically (O_EXCL); a file older than the TTL
    counts as free again and is reclaimed.
    """

    def __init__(self, directory: str | os.PathLike, ttl: float = 900, clock: Callable[[], float] = time.time):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        self._clock = clock

    def _path(self, key: str) -> Path:
        return self.dir / (hashlib.sha256(key.encode()).hexdigest() + ".nonce")

    def acquire(self, key: str) -> bool:
        p = self._path(key)
        for _ in range(2):
            try:
                fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                try:
                    age = self._clock() - p.stat().st_mtime
                except FileNotFoundError:
                    continue
                if age < self.ttl:
                    return False
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
                continue
            os.close(fd)
            return True
        return False

    def release(self, key: str) -> None:
        try:
            self._path(key).unlink()
        except FileNotFoundError:
            pass
