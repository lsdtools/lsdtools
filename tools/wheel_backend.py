"""The PEP 517 build backend of the lsdtools front door: standard library only, byte-reproducible.

It builds the tree ``lsdtools/wheel/generate.py`` writes (github.com/lsdtools/lsdtools holds that tree), so
``pip install .``, ``python -m build`` and the release pipeline make the same bytes from it:
- members sorted, every timestamp the tree's ``source_date_epoch``, fixed modes and host system;
- stored, not deflated: zlib and zlib-ng compress the same bytes differently across Python builds;
- the metadata comes from ``wheel.json`` beside it (no TOML parser needed on Python 3.10).
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import tarfile
import time
import zipfile
from pathlib import Path

__all__ = ["build_sdist", "build_wheel", "get_requires_for_build_sdist", "get_requires_for_build_wheel"]

TREE = Path(__file__).resolve().parents[1]


def _meta() -> dict:
    return json.loads((TREE / "wheel.json").read_text("utf-8"))


def _metadata(meta: dict) -> bytes:
    lines = [
        "Metadata-Version: 2.4", f"Name: {meta['name']}", f"Version: {meta['version']}",
        f"Summary: {meta['summary']}", f"Author: {meta['author']}", f"License-Expression: {meta['license']}",
        "License-File: LICENSE", f"Requires-Python: {meta['requires_python']}",
        *(f"Requires-Dist: {requirement}" for requirement in meta["dependencies"]),
        *(f"Project-URL: {label}, {url}" for label, url in meta["urls"]),
        *(f"Classifier: {classifier}" for classifier in meta["classifiers"]),
        "Description-Content-Type: text/markdown",
    ]
    return ("\n".join(lines) + "\n\n" + (TREE / "README.md").read_text("utf-8")).encode("utf-8")


def _date_time(meta: dict) -> tuple:
    return time.gmtime(max(int(meta["source_date_epoch"]), 315532800))[:6]  # zip cannot hold dates before 1980


def _files(root: Path) -> list[Path]:
    return sorted((path for path in root.rglob("*") if path.is_file() and "__pycache__" not in path.parts),
                  key=lambda path: path.relative_to(root).as_posix())


def _sdist_files() -> list[Path]:
    """The exported tree's files: what PROVENANCE.json names and itself. A checkout's .git, a build's dist
    and the release records (which hold the sdist's own sha256) are never part of it."""
    provenance = TREE / "PROVENANCE.json"
    if not provenance.is_file():
        return _files(TREE)
    names = sorted([*json.loads(provenance.read_text("utf-8"))["files"], "PROVENANCE.json"])
    return [TREE / name for name in names]


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None) -> str:
    meta = _meta()
    name, version = meta["name"], meta["version"]
    dist_info = f"{name}-{version}.dist-info"
    entries: list[tuple[str, bytes]] = []
    package_root = TREE / "src"
    for path in _files(package_root):
        entries.append((path.relative_to(package_root).as_posix(), path.read_bytes()))
    scripts = "".join(f"{script} = {target}\n" for script, target in meta["scripts"])
    gui_scripts = "".join(f"{script} = {target}\n" for script, target in meta["gui_scripts"])
    entries += [
        (f"{dist_info}/METADATA", _metadata(meta)),
        (f"{dist_info}/WHEEL", b"Wheel-Version: 1.0\nGenerator: lsdtools-backend 1\nRoot-Is-Purelib: true\n"
                               b"Tag: py3-none-any\n"),
        (f"{dist_info}/entry_points.txt",
         f"[console_scripts]\n{scripts}\n[gui_scripts]\n{gui_scripts}".encode("utf-8")),
        (f"{dist_info}/licenses/LICENSE", (TREE / "LICENSE").read_bytes()),
    ]
    record = "".join(f"{path},{_record_hash(data)},{len(data)}\n" for path, data in entries)
    entries.append((f"{dist_info}/RECORD", (record + f"{dist_info}/RECORD,,\n").encode("utf-8")))
    filename = f"{name}-{version}-py3-none-any.whl"
    stamp = _date_time(meta)
    with zipfile.ZipFile(os.path.join(wheel_directory, filename), "w", zipfile.ZIP_STORED) as wheel:
        for path, data in entries:
            info = zipfile.ZipInfo(path, date_time=stamp)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            wheel.writestr(info, data, compress_type=zipfile.ZIP_STORED)
    return filename


def build_sdist(sdist_directory, config_settings=None) -> str:
    meta = _meta()
    base = f"{meta['name']}-{meta['version']}"
    epoch = max(int(meta["source_date_epoch"]), 315532800)
    members = [(f"{base}/{path.relative_to(TREE).as_posix()}", path.read_bytes()) for path in _sdist_files()]
    members.append((f"{base}/PKG-INFO", _metadata(meta)))
    filename = f"{base}.tar.gz"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path, data in sorted(members):
            info = tarfile.TarInfo(path)
            info.size, info.mtime, info.mode = len(data), epoch, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    with open(os.path.join(sdist_directory, filename), "wb") as handle:
        handle.write(_gzip_stored(buffer.getvalue(), epoch))
    return filename


def _gzip_stored(data: bytes, mtime: int) -> bytes:
    """One gzip member whose deflate stream is stored blocks, so every interpreter writes the same bytes.

    CPython on Windows deflates with zlib-ng and elsewhere with zlib, and the two compress the same tar
    differently; a stored stream has one encoding, so the sdist's sha256 depends on its contents alone."""
    import struct
    import zlib

    out = bytearray(b"\x1f\x8b\x08\x00" + struct.pack("<I", mtime) + b"\x00\xff")  # deflate, no flags, OS unknown
    view = memoryview(data)
    for offset in range(0, max(len(data), 1), 0xFFFF):
        chunk = view[offset:offset + 0xFFFF]
        final = offset + 0xFFFF >= len(data)
        out += bytes([1 if final else 0]) + struct.pack("<HH", len(chunk), len(chunk) ^ 0xFFFF) + chunk
    out += struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF)
    return bytes(out)


def get_requires_for_build_wheel(config_settings=None) -> list:
    return []


def get_requires_for_build_sdist(config_settings=None) -> list:
    return []
