"""The sealed archive profile (runtime-store-v1 ``archives``) and the tree digest (``tree_digest``).

``extract`` accepts exactly one checksummed, content-sized Zstandard frame around a small POSIX USTAR
profile and nothing else: fixed ownership, files 0644 and directories 0755 only, sorted portable paths
with explicit parents, no receipts inside. It hashes the tree and the critical files as it writes them.
A Base (``profile="base"``) is exactly ``python/`` and ``dependencies/``; a Desktop delta
(``profile="delta"``) is extracted over its materialized Base, holds the executables and the app bundle,
and touches neither of those folders.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import NamedTuple

from .errors import ManagerError
from .paths import WINDOWS, child, long_path

__all__ = ["Extracted", "MANIFEST_NAME", "extract", "index_sha256", "tree_sha256"]

MANIFEST_NAME = "runtime-manifest-v1.json"
_RECEIPTS = frozenset({MANIFEST_NAME, "base-receipt-v1.json"})
_DOMAIN = b"LSD-RUNTIME-TREE-v1\0"
_COMPONENT = re.compile(r"[A-Za-z0-9._+@-]+")
_DEVICE = re.compile(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])", re.IGNORECASE)
_MAX_MEMBERS = 100_000
_MAX_FILE = 8 * 1024 ** 3
_MAX_TOTAL = 16 * 1024 ** 3
_CHUNK = 1 << 20
_PROFILES = {
    # required top-level names, reserved names that must not appear
    "base": (("python", "dependencies"), ("LSDDesktop.exe", "LSDCli.exe", "bundles")),
    "delta": (("LSDDesktop.exe", "LSDCli.exe", "bundles/app.pak"), ("python", "dependencies")),
}
_CRITICAL = ("LSDDesktop.exe", "LSDCli.exe", "bundles/app.pak")


def _bad(message: str) -> ManagerError:
    return ManagerError("invalid_data", f"the archive {message}")


def portable_path(value: str) -> str:
    """``value`` if it is a tree_digest path; ``invalid_data`` otherwise."""
    if not value or len(value) > 255 or not value.isascii() or "\\" in value or value.startswith("/"):
        raise _bad(f"has an unportable path {value!r}")
    for part in value.split("/"):
        if (part in ("", ".", "..") or part.endswith(".") or _COMPONENT.fullmatch(part) is None
                or _DEVICE.fullmatch(part.split(".", 1)[0])):
            raise _bad(f"has an unportable path {value!r}")
        if part.casefold() in _RECEIPTS:
            raise _bad(f"embeds a receipt at {value!r}")
    return value


def _octal(field: bytes, label: str) -> int:
    if not field or field[0] & 0x80:
        raise _bad(f"uses a non-octal {label}")
    start = 0
    while start < len(field) and field[start] in (0, 0x20):
        start += 1
    end = start
    while end < len(field) and 0x30 <= field[end] <= 0x37:
        end += 1
    if any(byte not in (0, 0x20) for byte in field[end:]):
        raise _bad(f"has an invalid {label}")
    return int(field[start:end] or b"0", 8)


def _text(field: bytes) -> str:
    end = field.find(b"\0")
    if end >= 0 and field[end:].strip(b"\0"):
        raise _bad("has a header string with data after its NUL")
    raw = field if end < 0 else field[:end]
    if not raw.isascii():
        raise _bad("has a header string that is not ASCII")
    return raw.decode("ascii")


class _Frame:
    """The decompressed bytes of exactly one sealed Zstandard frame, read in order."""

    def __init__(self, handle, zstandard) -> None:
        prefix = handle.read(18)
        try:
            parameters = zstandard.get_frame_parameters(prefix)
        except zstandard.ZstdError:
            raise _bad("does not start with a Zstandard frame header") from None
        if not parameters.has_checksum or parameters.dict_id != 0:
            raise _bad("is a Zstandard frame without a checksum, or with a dictionary")
        if parameters.content_size in (zstandard.CONTENTSIZE_UNKNOWN, zstandard.CONTENTSIZE_ERROR) or not (
                0 < parameters.content_size <= _MAX_TOTAL) or not 0 < parameters.window_size <= _MAX_TOTAL:
            raise _bad("declares a size outside the sealed profile")
        self._handle, self._zstandard = handle, zstandard
        self._decoder = zstandard.ZstdDecompressor().decompressobj()
        self._input = prefix
        self._buffer = bytearray()
        self._offset = 0
        self._expanded = 0
        self._size = parameters.content_size
        self._done = False

    def _pull(self) -> None:
        """Decompress the next compressed chunk onto the buffer."""
        chunk = self._input or self._handle.read(_CHUNK)
        self._input = b""
        if not chunk:
            raise _bad("is truncated")
        try:
            output = self._decoder.decompress(chunk)
        except self._zstandard.ZstdError:
            raise _bad("has a corrupt Zstandard frame") from None
        if self._decoder.unused_data or self._decoder.unconsumed_tail:
            raise _bad("has data after its Zstandard frame")
        if self._decoder.eof:
            if self._handle.read(1):
                raise _bad("has data after its Zstandard frame")
            self._done = True
        self._expanded += len(output)
        if self._expanded > self._size:
            raise _bad("expands past its declared size")
        if self._offset:
            del self._buffer[:self._offset]
            self._offset = 0
        self._buffer += output

    def _fill(self, need: int) -> None:
        while len(self._buffer) - self._offset < need:
            if self._done:
                raise _bad("ends inside a member")
            self._pull()

    def read(self, size: int) -> bytes:
        """The next ``size`` bytes, copied: the buffer behind them is compacted on the next read."""
        self._fill(size)
        with memoryview(self._buffer) as view:
            data = view[self._offset:self._offset + size].tobytes()
        self._offset += size
        return data

    def finish(self) -> None:
        """Drain the frame: after the end marker only zero blocks (a tar writer's record padding) may follow."""
        while not self._done:
            self._pull()
        rest = len(self._buffer) - self._offset
        if self._expanded != self._size or rest % 512 or self._buffer[self._offset:].strip(b"\0"):
            raise _bad("has bytes after its USTAR end marker")
        self._offset = len(self._buffer)


class Extracted(NamedTuple):  # a NamedTuple: a launch imports no dataclasses
    tree_sha256: str           # the tree_digest of the members extracted
    critical: dict             # LSDDesktop.exe / LSDCli.exe / bundles/app.pak -> sha256 (a delta's)
    members: int
    expanded_bytes: int
    index: tuple = ()          # (path, size, sha256) per file and (path, None, None) per folder, sorted


def index_sha256(index) -> str:
    """The tree_digest of a tree described by ``index`` (records as ``Extracted.index``), read from nothing."""
    digest = hashlib.sha256(_DOMAIN)
    for path, size, sha in sorted(index, key=lambda record: record[0].encode("ascii")):
        encoded = path.encode("ascii")
        if size is None:
            digest.update(b"D\0" + encoded + b"\0")
        else:
            digest.update(b"F\0" + encoded + b"\0" + str(size).encode("ascii") + b"\0" + bytes.fromhex(sha))
    return digest.hexdigest()


def extract(archive: Path, destination: Path, *, profile: str) -> Extracted:
    """Extract ``archive`` into ``destination`` (a new folder for a Base; the materialized Base for a delta)."""
    import zstandard

    required, reserved = _PROFILES[profile]
    root = long_path(destination)
    if profile == "base":
        os.mkdir(root)
    elif not os.path.isdir(root):
        raise ManagerError("internal", f"a delta extracts over its Base, and {destination} is not one")
    tree = hashlib.sha256(_DOMAIN)
    names: set[str] = set()
    directories = {""}
    critical: dict[str, str] = {}
    index: list[tuple] = []
    previous = ""
    members = total = zero = 0
    with open(long_path(archive), "rb") as handle:
        frame = _Frame(handle, zstandard)
        while True:
            header = frame.read(512)
            if not header.strip(b"\0"):
                zero += 1
                if zero == 2:
                    break
                continue
            if zero:
                raise _bad("has a member after a zero block")
            members += 1
            if members > _MAX_MEMBERS:
                raise _bad(f"has more than {_MAX_MEMBERS} members")
            checksum = sum(header[:148]) + 8 * 0x20 + sum(header[156:])
            if _octal(header[148:156], "checksum") != checksum:
                raise _bad("has a header whose checksum does not match")
            if header[257:263] != b"ustar\0" or header[263:265] != b"00":
                raise _bad("is not POSIX USTAR")
            if (_octal(header[108:116], "uid") or _octal(header[116:124], "gid")
                    or _octal(header[136:148], "mtime") or _text(header[157:257]) or _text(header[265:297])
                    or _text(header[297:329]) or _octal(header[329:337], "device major")
                    or _octal(header[337:345], "device minor") or header[500:512].strip(b"\0")):
                raise _bad("has ownership, link or extension metadata")
            kind = header[156:157]
            if kind not in (b"0", b"5"):
                raise _bad("has a link, device or extension member")
            directory = kind == b"5"
            size = _octal(header[124:136], "size")
            mode = _octal(header[100:108], "mode")
            if (directory and (size or mode != 0o755)) or (not directory and (mode != 0o644 or size > _MAX_FILE)):
                raise _bad("has a member whose size or mode is outside the sealed profile")
            prefix, name = _text(header[345:500]), _text(header[0:100])
            raw = f"{prefix}/{name}" if prefix else name
            path = portable_path(raw[:-1] if directory and raw.endswith("/") else raw)
            if previous and path.encode("ascii") <= previous.encode("ascii"):
                raise _bad("is not strictly sorted by path")
            previous = path
            folded = path.casefold()
            if folded in names:
                raise _bad(f"repeats {path!r} (Windows folds case)")
            names.add(folded)
            parent = path.rpartition("/")[0]
            if parent.casefold() not in directories:
                raise _bad(f"has {path!r} before its parent")
            target = child(root, path)
            encoded = path.encode("ascii")
            if directory:
                os.mkdir(target)
                directories.add(folded)
                tree.update(b"D\0" + encoded + b"\0")
                index.append((path, None, None))
                continue
            total += size
            if total > _MAX_TOTAL:
                raise _bad("expands past 16 GiB")
            digest = hashlib.sha256()
            with open(target, "xb") as output:
                remaining = size
                while remaining:
                    take = min(remaining, _CHUNK)
                    data = frame.read(take)
                    output.write(data)
                    digest.update(data)
                    remaining -= take
            padding = (-size) % 512
            if padding and frame.read(padding).strip(b"\0"):
                raise _bad(f"has non-zero padding after {path!r}")
            tree.update(b"F\0" + encoded + b"\0" + str(size).encode("ascii") + b"\0" + digest.digest())
            index.append((path, size, digest.hexdigest()))
            if path in _CRITICAL:
                critical[path] = digest.hexdigest()
        frame.finish()
    for name in required:
        if name.casefold() not in names:
            raise _bad(f"lacks {name}, which a {profile} archive holds")
    for name in reserved:
        if name.casefold() in names:
            raise _bad(f"holds {name}, which a {profile} archive never does")
    return Extracted(tree.hexdigest(), critical, members, total, tuple(index))


def tree_sha256(root: Path, *, members: list | None = None, index: list | None = None) -> str:
    """The tree_digest of the tree at ``root`` (its top-level runtime-manifest-v1.json excluded), reading every
    file. ``members`` receives the paths and ``index`` the ``Extracted.index`` records."""
    base = long_path(root)
    found: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    pending = [""]
    while pending:
        relative = pending.pop()
        with os.scandir(child(base, relative)) as entries:
            for entry in entries:
                path = f"{relative}/{entry.name}" if relative else entry.name
                if path == MANIFEST_NAME:
                    continue
                if entry.is_symlink() or (WINDOWS and entry.stat(follow_symlinks=False).st_file_attributes & 0x400):
                    raise ManagerError("trust", f"{root} holds a link or reparse point at {path!r}")
                if path.casefold() in seen:
                    raise ManagerError("trust", f"{root} holds two paths Windows cannot tell apart: {path!r}")
                seen.add(path.casefold())
                try:
                    portable_path(path)
                except ManagerError as exc:
                    raise ManagerError("trust", f"{root}: {exc.message}") from None
                if entry.is_dir(follow_symlinks=False):
                    found.append((path, child(base, path), True))
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    found.append((path, child(base, path), False))
                else:
                    raise ManagerError("trust", f"{root} holds a member that is neither file nor folder: {path!r}")
                if len(found) > _MAX_MEMBERS:
                    raise ManagerError("trust", f"{root} has more than {_MAX_MEMBERS} members")
    found.sort(key=lambda item: item[0].encode("ascii"))
    digest = hashlib.sha256(_DOMAIN)
    for path, full, directory in found:
        encoded = path.encode("ascii")
        if directory:
            digest.update(b"D\0" + encoded + b"\0")
            if index is not None:
                index.append((path, None, None))
            continue
        content = hashlib.sha256()
        size = 0
        with open(full, "rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                content.update(chunk)
                size += len(chunk)
        digest.update(b"F\0" + encoded + b"\0" + str(size).encode("ascii") + b"\0" + content.digest())
        if index is not None:
            index.append((path, size, content.hexdigest()))
    if members is not None:
        members.extend(path for path, _full, _directory in found)
    return digest.hexdigest()
