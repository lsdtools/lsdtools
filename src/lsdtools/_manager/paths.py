"""Where a home and its runtime store are, which platform this is, and paths Windows cannot limit.

A home is ``LSD_HOME`` when set, else the target's default (runtime-store-v1 ``homes``). Runtime trees
are deep and their roots carry a 64-hex digest, so on Windows every filesystem call below a store uses an
extended-length path (``\\\\?\\``), which MAX_PATH does not bound.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .errors import ManagerError

__all__ = ["WINDOWS", "child", "default_home", "long_path", "platform_id", "resolve_home", "store_root"]

WINDOWS = sys.platform.startswith("win")
_ARCHES = {"amd64": "x86_64", "x86_64": "x86_64", "x64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}


def platform_id() -> tuple[str, str]:
    """(platform, arch) as runtime-platforms-v1 spells them."""
    if WINDOWS:
        system = "windows"
    elif sys.platform.startswith("linux"):
        system = "linux"
    elif sys.platform == "darwin":
        system = "macos"
    else:
        raise ManagerError("platform_unavailable", f"LSD has no runtime for {sys.platform}")
    machine = _machine()
    arch = _ARCHES.get(machine.lower())
    if arch is None:
        raise ManagerError("platform_unavailable", f"LSD has no runtime for the {machine} processor")
    return system, arch


def _machine() -> str:
    """The processor, read where it is free: Windows' environment (``platform.machine()`` asks WMI there,
    about 0.1 s), else ``uname``."""
    if WINDOWS:
        named = os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE")
        if named:
            return named
        import platform

        return platform.machine()
    return os.uname().machine


def default_home(target: str) -> Path:
    suffix = "" if target == "production" else "-" + target
    if WINDOWS:
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise ManagerError("unavailable", "LOCALAPPDATA is not set", hint="set LSD_HOME or pass --home")
        return Path(base) / ("LSD" + suffix)
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / ("LSD" + suffix)
    data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data) / ("lsd" + suffix)


def resolve_home(home: str | None, target: str) -> Path:
    value = home or os.environ.get("LSD_HOME")
    path = Path(value) if value else default_home(target)
    return Path(os.path.abspath(path))


def store_root(home: Path, store: str | None = None) -> Path:
    value = store or os.environ.get("LSDTOOLS_STORE")
    return Path(os.path.abspath(value)) if value else home / "runtime"


def long_path(path: str | os.PathLike) -> str:
    """``path`` for an OS call: absolute, and extended-length on Windows.

    An extended-length path takes only backslashes, and an MSYS interpreter spells its own paths with
    forward slashes, so separators are normalized here and children are joined with ``child``."""
    text = os.fspath(path)
    if not WINDOWS:
        return os.path.abspath(text)
    if text.startswith(("\\\\?\\", "//?/")):
        return "\\\\?\\" + text[4:].replace("/", "\\")
    text = os.path.abspath(text).replace("/", "\\")
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


def child(base: str, relative: str) -> str:
    """``base`` (a ``long_path``) joined with a '/'-separated relative path, in the OS's spelling."""
    if not relative:
        return base
    return base + "\\" + relative.replace("/", "\\") if WINDOWS else os.path.join(base, relative)
