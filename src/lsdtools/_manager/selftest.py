"""``lsdtools selftest``: the suite of github.com/lsdtools/selftest, run on this machine against this lsdtools.

The suite (``selftest/selftest.py`` beside the kernel's test packages in that repository) is the same file a
developer runs in a checkout. Here it is one release archive pinned by its exact size and sha256: downloaded
once from GitHub Releases into ``<home>/selftest/<sha256>/``, extracted with portable paths only, then run in
an isolated Python (``-I``) that drives this lsdtools (``python -m lsdtools._manager``) in a scratch home
sharing this home's runtimes. ``--from DIR`` runs a checkout's suite instead. Each step the suite reports
is a note as it ends; its ``lsd.selftest.v1`` report is the result.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from .archive import portable_path
from .errors import ManagerError
from .paths import long_path

__all__ = ["SUITE", "fetch", "run"]

#: The release of github.com/lsdtools/selftest this lsdtools runs.
SUITE = {
    "version": "1.0.0",
    "url": "https://github.com/lsdtools/selftest/releases/download/v1.0.0/selftest-1.0.0.zip",
    "size": 28555,
    "sha256": "2bca6fb030c3c1f9a4d3367d0f979c69d0a43a3ec83363f7b7645018d4ce28e8",
}
_SCRIPT = "selftest/selftest.py"
_MAX_MEMBERS = 4096
_MAX_BYTES = 64 * 1024 ** 2


def _extract(archive: Path, destination: Path, prefix: str) -> None:
    """Every member under ``prefix``, at a portable path, within the size bounds; nothing else."""
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > _MAX_MEMBERS or sum(item.file_size for item in members) > _MAX_BYTES:
            raise ManagerError("invalid_data", "the selftest archive is larger than a suite")
        for item in members:
            name = item.filename
            if not name.startswith(prefix):
                raise ManagerError("invalid_data", f"the selftest archive has {name!r} outside {prefix}")
            relative = name[len(prefix):].rstrip("/")
            if not relative:
                continue
            portable_path(relative)
            target = destination.joinpath(*relative.split("/"))
            if item.is_dir():
                os.makedirs(long_path(target), exist_ok=True)
                continue
            os.makedirs(long_path(target.parent), exist_ok=True)
            with bundle.open(item) as source, open(long_path(target), "wb") as written:
                shutil.copyfileobj(source, written)


def fetch(home: Path, transport, *, progress=None) -> Path:
    """The pinned suite's folder, downloaded and extracted on first use."""
    root = home / "selftest" / SUITE["sha256"]
    suite = root / f"lsd-selftest-{SUITE['version']}"
    if (suite / _SCRIPT).is_file():
        return suite
    os.makedirs(long_path(root), exist_ok=True)
    part = transport.download_mirror(SUITE["url"], root / "suite.zip.part", size=SUITE["size"],
                                     sha256=SUITE["sha256"], progress=progress)
    staging = root / "extracting"
    shutil.rmtree(long_path(staging), ignore_errors=True)
    _extract(part, staging, f"lsd-selftest-{SUITE['version']}/")
    if not (staging / _SCRIPT).is_file():
        raise ManagerError("invalid_data", f"the selftest archive has no {_SCRIPT}")
    os.replace(long_path(staging), long_path(suite))
    os.remove(long_path(part))
    return suite


def run(suite: Path, *, home: Path, store: str | None, target: str | None, keep: bool, note) -> dict:
    """Run ``suite``'s selftest against this lsdtools; its report, each step noted as it ends."""
    script = suite / _SCRIPT
    if not script.is_file():
        raise ManagerError("not_found", f"{suite} has no {_SCRIPT}", hint="a checkout of github.com/lsdtools/selftest")
    command = [sys.executable, "-I", str(script), "--lsdtools-python", sys.executable, "--json",
               *(["--target", target] if target else []), *(["--keep"] if keep else [])]
    environment = {**os.environ, "LSD_HOME": str(home)}
    if store:
        environment["LSDTOOLS_STORE"] = store
    # The suite's own folder is the working directory: nothing in the caller's shadows lsdtools for -m.
    process = subprocess.Popen(command, cwd=str(suite), env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                               errors="replace")
    for line in process.stderr:
        if line.strip():
            note(line.rstrip())
    output = process.stdout.read()
    status = process.wait()
    lines = [line for line in output.splitlines() if line.startswith("{")]
    if not lines:
        raise ManagerError("failed", f"the selftest exited {status} without a report")
    report = json.loads(lines[-1])
    if report.get("schema") != "lsd.selftest.v1":
        raise ManagerError("protocol", "the selftest's report is not lsd.selftest.v1")
    return report
