"""The lsdtools-cli-v1 result document and progress lines, and the global options every command reads.

Both halves of the command line use it: the outer manager in the user's Python, and the runtime commands
inside a runtime (``LSDCli.exe lsdtools``), so one document shape and one exit-status table serve both.
"""
from __future__ import annotations

import json
import os
import sys
import time

from . import VERSION
from .errors import ManagerError

__all__ = ["GLOBAL_FLAGS", "GLOBAL_VALUES", "Options", "Reporter", "split_globals"]

GLOBAL_VALUES = ("--home", "--store", "--target", "--track", "--runtime")
GLOBAL_FLAGS = ("--json", "--offline", "--no-auto-setup")
# lsdtools-cli-v1 "Global options": also among the command's own options (an agent writes ``lsdtools
# list --json``), up to a ``--``; ``setup``'s own ``--runtime`` is its own; nothing after ``python`` or
# ``test``, whose arguments are the program's.
_PASSTHROUGH = ("python", "test")


class Options:
    def __init__(self) -> None:
        self.json = os.environ.get("LSDTOOLS_JSON") == "1"
        self.home = None
        self.store = None
        self.target = os.environ.get("LSDTOOLS_TARGET") or "production"
        self.track = os.environ.get("LSDTOOLS_TRACK") or None
        self.runtime = os.environ.get("LSDTOOLS_RUNTIME") or None
        self.offline = os.environ.get("LSDTOOLS_OFFLINE") == "1"
        self.no_auto_setup = os.environ.get("LSDTOOLS_NO_AUTO_SETUP") == "1"


def _take(options: Options, argv: list[str], index: int, values: tuple[str, ...]) -> int | None:
    """Read the global option at *index* into *options*; the index after it, or None when it is not one."""
    arg = argv[index]
    name, equals, value = arg.partition("=")
    if name in values:
        if not equals:
            index += 1
            if index >= len(argv):
                raise ManagerError("usage", f"{name} needs a value")
            value = argv[index]
        setattr(options, name[2:].replace("-", "_"), value)
        return index + 1
    if arg in GLOBAL_FLAGS:
        setattr(options, arg[2:].replace("-", "_"), True)
        return index + 1
    return None


def split_globals(argv: list[str]) -> tuple[Options, list[str]]:
    """The global options, and the command's own argv without them (otherwise in order)."""
    options = Options()
    index = 0
    while index < len(argv) and (after := _take(options, argv, index, GLOBAL_VALUES)) is not None:
        index = after
    rest = argv[index:]
    if not rest or rest[0] in _PASSTHROUGH:
        return options, rest
    kept, position = [rest[0]], 1
    while position < len(rest):
        if rest[position] == "--":
            kept.extend(rest[position:])
            break
        after = _take(options, rest, position,
                      GLOBAL_VALUES if rest[0] != "setup" else tuple(v for v in GLOBAL_VALUES if v != "--runtime"))
        if after is None:
            kept.append(rest[position])
            position += 1
        else:
            position = after
    return options, kept


class Reporter:
    """The result document and progress, as text or as lsdtools-cli-v1 JSON."""

    def __init__(self, options: Options, command: str) -> None:
        self.options, self.command = options, command
        self.started = time.monotonic()
        self.warnings: list[dict] = []
        self.runtime: dict | None = None
        self._last = 0.0

    def progress(self, label: str, done: int, total: int) -> None:
        now = time.monotonic()
        if done < total and now - self._last < 0.5:
            return
        self._last = now
        if self.options.json:
            print(json.dumps({"schema": "lsdtools.progress.v1", "event": "download", "label": label,
                              "done": done, "total": total}), file=sys.stderr, flush=True)
        else:
            print(f"  {label}: {done * 100 // max(total, 1)}% of {total / 1e6:.0f} MB", file=sys.stderr, flush=True)

    def note(self, text: str) -> None:
        if self.options.json:
            print(json.dumps({"schema": "lsdtools.progress.v1", "event": "note", "message": text}),
                  file=sys.stderr, flush=True)
        else:
            print(text, file=sys.stderr, flush=True)

    def warn(self, code: str, message: str) -> None:
        self.warnings.append({"code": code, "message": message})
        if not self.options.json:
            print(f"warning: {message}", file=sys.stderr)

    def finish(self, data: dict | None, text: str, error: ManagerError | None = None) -> int:
        if self.options.json:
            print(json.dumps({
                "schema": "lsdtools.result.v1", "command": self.command, "ok": error is None,
                "data": data if error is None else error.data, "warnings": self.warnings,
                "error": None if error is None else error.to_json(), "lsdtools": VERSION,
                "runtime": self.runtime, "elapsed_ms": int((time.monotonic() - self.started) * 1000),
            }, indent=None), flush=True)
        elif error is None:
            if text:
                print(text)
        else:
            print(f"error: {error.message}", file=sys.stderr)
            if error.hint:
                print(f"hint: {error.hint}", file=sys.stderr)
        return 0 if error is None else error.status
