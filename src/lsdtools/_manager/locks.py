"""The store's writer lock: runtime-store-v1 ``locks.store``.

One exclusive advisory lock on ``<store>/.lock`` for a whole install, repair, removal or gc, released by
the OS if the holder dies. Every writer of a store's ledger holds it.
"""
from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from .errors import ManagerError
from .paths import WINDOWS, long_path

__all__ = ["store_lock"]


def _try_lock(fd: int) -> bool:
    try:
        if WINDOWS:
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock(fd: int) -> None:
    if WINDOWS:
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def store_lock(store: Path, *, timeout: float = 600.0, waiting: Callable[[], None] | None = None) -> Iterator[None]:
    """Hold ``<store>/.lock`` for the block, waiting up to ``timeout`` seconds for another writer."""
    os.makedirs(long_path(store), exist_ok=True)
    fd = os.open(long_path(store / ".lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
    try:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        deadline = time.monotonic() + timeout
        delay, announced = 0.05, False
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise ManagerError("temporary", f"another lsdtools is writing {store}",
                                   hint="wait for it to finish, then retry")
            if waiting is not None and not announced:
                waiting()
                announced = True
            time.sleep(delay)  # waiting for another process's lock, not for readiness
            delay = min(delay * 2, 1.0)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)
