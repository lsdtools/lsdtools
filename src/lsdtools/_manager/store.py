"""The runtime store (runtime-store-v1): read and verify its runtimes, install, repair and remove them.

Readers take no lock: a ledger is replaced atomically, so they see the old one or the new one. Every
writer holds ``locks.store_lock`` for its whole operation. A runtime directory is never authority by its
name: only a ledger row whose manifest bytes are canonical, match its digest, carry a valid signature
under the target's Updates key and describe the files on disk. A runtime is verified when it is installed
and trusted at launch; ``Verify`` says how much a caller re-reads:
- ``ROW``: the row, its manifest and the required files (a listing, every launch);
- ``SIGNED``: and the manifest's signature and the executables' sha256 (``runtime verify``, ``doctor``);
- ``FULL``: and the whole payload tree (install, repair, ``runtime verify --full``).
"""
from __future__ import annotations

import enum
import os
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable, NamedTuple

from .archive import MANIFEST_NAME, extract, index_sha256, tree_sha256
from .canonical import canonical_bytes, sha256_bytes, sha256_file, strict_loads
from .manifests import check_base_manifest, check_runtime_manifest, version_key
from .mirrors import mirror_url
from .ed25519 import verify as verify_signature
from .errors import ManagerError
from .paths import WINDOWS, child, long_path
from .targets import Target

if TYPE_CHECKING:  # a launch reads the store; only an install reaches the server
    from .catalog import Catalog, CatalogRow
    from .transport import Transport

__all__ = ["Installation", "Store", "Verify"]

LEDGER = "runtimes-v1.json"
STORE_FILE = "store-v1.json"
DEFAULT_FILE = "default-v1.json"
BASE_RECEIPT = "base-receipt-v1.json"
BASE_INDEX = "members-v1.json"
_MAX_LEDGER = 2 * 1024 * 1024
_MAX_MANIFEST = 256 * 1024
_MAX_INDEX = 64 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CHUNK = 1 << 20
_MAX_ROWS = 256
_DEBRIS = re.compile(r"\.[0-9a-f]{64}\.[0-9a-f]{12}\.(staging|retired)")


class Verify(enum.IntEnum):
    """How deep a runtime is checked. Verified at install (``FULL``) and on request, trusted at launch:

    - ``ROW``: what a launch reads. The ledger row, the manifest bytes it names, this platform, its files present;
    - ``SIGNED``: the manifest's signature and the executables' digests (``runtime verify``, ``doctor``);
    - ``FULL``: every file of the signed tree, and Authenticode where the release has it.
    """

    ROW = 1
    SIGNED = 2
    FULL = 3


class Installation(NamedTuple):
    """One ledgered runtime whose row and files verified to the requested depth (a NamedTuple: a launch imports
    no dataclasses)."""

    coordinate: dict
    root: Path
    manifest: dict
    manifest_sha256: str
    signature: dict

    @property
    def version(self) -> str:
        return self.coordinate["version"]

    @property
    def selector(self) -> str:
        return f"{self.version}/{self.coordinate['artifact_sha256']}"

    def executable(self, which: str) -> Path:
        return self.root / self.manifest[f"{which}_executable"]

    def to_json(self) -> dict:
        return {**self.coordinate, "root": str(self.root), "selector": self.selector,
                "published_at": self.manifest["published_at"],
                "base_version": self.manifest["runtime_base"]["version"]}


def _write_atomic(path: Path, data: bytes) -> None:
    """Replace ``path`` with ``data``: a flushed sibling temporary renamed over it."""
    temporary = path.with_name(f".{path.stem}.{os.urandom(6).hex()}.tmp")
    fd = os.open(long_path(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(long_path(temporary), long_path(path))
    except BaseException:
        try:
            os.remove(long_path(temporary))
        except OSError:
            pass  # the temporary never appeared, or is already gone -- never fatal
        raise
    if not WINDOWS:
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _copy_hashed(source: str, target: str) -> tuple[int, str]:
    """Copy ``source`` to a new ``target``; return the size and sha256 of the bytes copied."""
    import hashlib

    digest, size = hashlib.sha256(), 0
    with open(source, "rb") as reader, open(target, "xb") as writer:
        for chunk in iter(lambda: reader.read(_CHUNK), b""):
            writer.write(chunk)
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _remove(function, path: str) -> None:
    try:
        function(path)
    except PermissionError:
        os.chmod(path, 0o700)  # read-only: Windows refuses to delete it until it is writable
        function(path)


def _is_link(entry: os.DirEntry) -> bool:
    if entry.is_symlink():
        return True
    return WINDOWS and bool(entry.stat(follow_symlinks=False).st_file_attributes & 0x400)  # a junction


def _settle_times(path: str, moment: float) -> None:
    """Give every file and folder below ``path`` one modification time, each folder after its contents.

    The archives carry no times, so each file and folder took the moment it was written, and a folder that
    gained an entry after a cache beside it reads as newer than that cache. GTK then ignores an icon
    theme's ``icon-theme.cache`` and reads its hundreds of folders at every start, about 0.3 s per load;
    one time for the whole runtime leaves every such cache valid. Links are never followed."""
    stack = [(path, False)]
    while stack:
        folder, settled = stack.pop()
        if settled:
            os.utime(folder, (moment, moment))
            continue
        stack.append((folder, True))
        with os.scandir(folder) as entries:
            for entry in entries:
                if _is_link(entry):
                    continue
                full = child(folder, entry.name)
                if entry.is_dir(follow_symlinks=False):
                    stack.append((full, False))
                else:
                    os.utime(full, (moment, moment))


#: What a launch loads as code. Windows' malware scan reads a new file of these in full the first time
#: anything opens it, and a runtime holds about 270 MB of them: unread, a first launch waited on that scan
#: (18 s, measured 2026-10-27); read once at install, the first open after it took 3.1 s.
_EXECUTABLE_SUFFIXES = (".exe", ".dll", ".pyd")


def _read_file(path: str) -> None:
    with open(path, "rb") as handle:
        while handle.read(_CHUNK):
            pass


def _read_executables(root: str) -> None:
    """Read every executable file below ``root`` once, largest first, on a few threads (Windows only), so that
    the malware scan of a new file happens during the install rather than during a launch. Links are never
    followed; a file the scan withholds is a broken runtime, reported now instead of at its first launch."""
    if not WINDOWS:
        return
    from concurrent.futures import ThreadPoolExecutor

    found, stack = [], [root]
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                if _is_link(entry):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                elif entry.name.lower().endswith(_EXECUTABLE_SUFFIXES):
                    found.append((entry.stat(follow_symlinks=False).st_size, entry.path))
    with ThreadPoolExecutor(max_workers=4) as pool:
        for path, done in [(path, pool.submit(_read_file, path)) for _size, path in sorted(found, reverse=True)]:
            try:
                done.result()
            except OSError as exc:
                raise ManagerError("unavailable", f"{path} could not be read after it was installed: {exc}",
                                   hint="an antivirus may have withheld it") from None


def _in_background(function, *args):
    """``function(*args)`` on a thread; the answer's ``result()`` waits for it and raises what it raised."""
    import threading
    from concurrent.futures import Future

    answer = Future()

    def run():
        try:
            answer.set_result(function(*args))
        except BaseException as exc:  # handed to whoever waits on the answer
            answer.set_exception(exc)

    threading.Thread(target=run, name="lsdtools-read-executables", daemon=True).start()
    return answer


def _remove_tree(path: str) -> None:
    """Delete ``path`` and everything below it, never following a link (stdlib's walkers join with
    ``os.sep``, which an MSYS interpreter makes '/', and an extended-length path refuses '/')."""
    if not os.path.lexists(path):
        return
    if not os.path.isdir(path) or os.path.islink(path):
        _remove(os.remove, path)
        return
    stack = [(path, False)]
    while stack:
        folder, emptied = stack.pop()
        if emptied:
            _remove(os.rmdir, folder)
            continue
        stack.append((folder, True))
        with os.scandir(folder) as entries:
            for entry in entries:
                full = child(folder, entry.name)
                if _is_link(entry):
                    _remove(os.rmdir if entry.is_dir() else os.remove, full)  # the link, not its target
                elif entry.is_dir(follow_symlinks=False):
                    stack.append((full, False))
                else:
                    _remove(os.remove, full)


def _plain(path: str, *, directory: bool) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    if os.path.islink(path) or (WINDOWS and getattr(status, "st_file_attributes", 0) & 0x400):
        return False
    return os.path.isdir(path) if directory else os.path.isfile(path)


def _authenticode_ok(path: Path) -> bool:
    """WinVerifyTrust's generic policy accepts ``path`` (no revocation check, no UI)."""
    import ctypes
    from ctypes import wintypes

    class FileInfo(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class TrustData(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(FileInfo)), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    class Guid(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8)]

    action = Guid(0xaac56b, 0xcd44, 0x11d0, (ctypes.c_ubyte * 8)(0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee))
    info = FileInfo(ctypes.sizeof(FileInfo), str(path), None, None)
    data = TrustData(cbStruct=ctypes.sizeof(TrustData), dwUIChoice=2, fdwRevocationChecks=0, dwUnionChoice=1,
                     pFile=ctypes.pointer(info), dwStateAction=0, dwProvFlags=0x10)  # WTD_REVOCATION_CHECK_NONE
    wintrust = ctypes.WinDLL("wintrust")
    wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(Guid), ctypes.POINTER(TrustData)]
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    return wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data)) == 0


class Store:
    """One target's runtime store for one platform."""

    def __init__(self, root: Path, target: Target, *, system: str, arch: str, platform: dict) -> None:
        self.root = Path(root)
        self.target = target
        self.system, self.arch, self.platform = system, arch, platform

    # -- reading ---------------------------------------------------------------------------------

    def _ledger(self) -> list[dict]:
        path = long_path(self.root / LEDGER)
        if not os.path.lexists(path):
            return []
        if not _plain(path, directory=False):
            raise ManagerError("trust", f"{self.root / LEDGER} is not a plain file")
        with open(path, "rb") as handle:
            document = strict_loads(handle.read(_MAX_LEDGER + 1), maximum=_MAX_LEDGER, label=LEDGER)
        if (type(document) is not dict or set(document) != {"schema_version", "installations"}
                or document["schema_version"] != 1 or type(document["installations"]) is not list
                or not 0 < len(document["installations"]) <= _MAX_ROWS):
            raise ManagerError("trust", f"{self.root / LEDGER} violates runtime-store-v1")
        return document["installations"]

    def _verified(self, row, depth: Verify) -> Installation:
        if type(row) is not dict or set(row) != {"coordinate", "manifest_sha256", "manifest_signature"}:
            raise ManagerError("trust", f"{LEDGER} has a row that violates runtime-store-v1")
        coordinate, signature = row["coordinate"], row["manifest_signature"]
        if type(coordinate) is not dict or type(coordinate.get("version")) is not str \
                or type(coordinate.get("artifact_sha256")) is not str:
            raise ManagerError("trust", f"{LEDGER} has a row with an invalid coordinate")
        label = f"runtime {coordinate['version']}"
        root = self.root / "versions" / coordinate["version"] / coordinate["artifact_sha256"]
        if not _plain(long_path(root), directory=True):
            raise ManagerError("trust", f"{label}'s folder is missing or not a plain folder", hint="lsdtools runtime "
                               f"install {coordinate['version']}/{coordinate['artifact_sha256'][:12]} repairs it")
        manifest_path = long_path(root / MANIFEST_NAME)
        if not _plain(manifest_path, directory=False):
            raise ManagerError("trust", f"{label} has no manifest")
        with open(manifest_path, "rb") as handle:
            raw = handle.read(_MAX_MANIFEST + 1)
        manifest = strict_loads(raw, maximum=_MAX_MANIFEST, label=f"{label}'s manifest")
        if canonical_bytes(manifest) != raw or sha256_bytes(raw) != row["manifest_sha256"]:
            raise ManagerError("trust", f"{label}'s manifest is not the bytes its ledger row names")
        keys = self.target.updates_keys
        if (type(signature) is not dict or set(signature) != {"algorithm", "key_id", "value"}
                or signature["algorithm"] != "ed25519" or signature["key_id"] not in keys):
            raise ManagerError("trust", f"{label} is not signed by a {self.target.name} Updates key")
        if depth >= Verify.SIGNED:
            verify_signature(raw, signature["value"], keys[signature["key_id"]])
        try:
            check_runtime_manifest(manifest, self.system, self.arch, self.platform)
        except ManagerError as exc:
            raise ManagerError("trust", f"{label}: {exc.message}") from None
        if manifest["coordinate"] != coordinate:
            raise ManagerError("trust", f"{label}'s ledger row and manifest name different runtimes")
        installation = Installation(coordinate, root, manifest, row["manifest_sha256"], signature)
        base = long_path(root)
        for name, directory in ((manifest["desktop_executable"], False), (manifest["cli_executable"], False),
                                (manifest["app_bundle"], False), ("python", True), ("dependencies", True)):
            if not _plain(child(base, name), directory=directory):
                raise ManagerError("trust", f"{label} is missing {name}")
        if depth >= Verify.SIGNED:
            for name, digest in ((manifest["desktop_executable"], manifest["desktop_executable_sha256"]),
                                 (manifest["cli_executable"], manifest["cli_executable_sha256"]),
                                 (manifest["app_bundle"], manifest["app_bundle_sha256"])):
                if sha256_file(child(base, name)) != digest:
                    raise ManagerError("trust", f"{label}'s {name} is not the signed file")
        if depth >= Verify.FULL:
            if tree_sha256(root) != manifest["payload_tree_sha256"]:
                raise ManagerError("trust", f"{label}'s files are not the signed tree", hint="lsdtools runtime "
                                   f"install {coordinate['version']}/{coordinate['artifact_sha256'][:12]} --repair")
            if WINDOWS:
                for which in ("desktop", "cli"):
                    if manifest[f"{which}_authenticode_verified"] and not _authenticode_ok(installation.executable(which)):
                        raise ManagerError("trust", f"{label}'s {which} executable fails its Authenticode check")
        return installation

    def installations(self, depth: Verify = Verify.ROW) -> list[Installation]:
        """Every ledgered runtime, newest first; any row that fails to verify fails the whole read."""
        rows = self._ledger()
        seen = set()
        result = []
        for row in rows:
            installation = self._verified(row, depth)
            key = (installation.version, installation.coordinate["artifact_sha256"])
            if key in seen:
                raise ManagerError("trust", f"{LEDGER} lists runtime {installation.selector} twice")
            seen.add(key)
            result.append(installation)
        return sorted(result, key=lambda item: (version_key(item.version), item.manifest["published_at"],
                                                item.coordinate["artifact_sha256"]), reverse=True)

    def find(self, selector: str, depth: Verify = Verify.ROW) -> Installation:
        """``latest``/``default``, ``x.y.z`` (its newest build here) or ``x.y.z/<12+ hex>``."""
        if selector in (None, "", "default"):
            installation = self.default(depth)
            if installation is None:
                raise ManagerError("not_found", "no runtime is installed", hint="lsdtools setup")
            return installation
        installed = self.installations(Verify.ROW)
        if selector == "latest":
            matches = installed[:1]
        else:
            version, _, prefix = selector.partition("/")
            matches = [item for item in installed if item.version == version
                       and item.coordinate["artifact_sha256"].startswith(prefix)]
            if prefix and len(matches) > 1:
                raise ManagerError("usage", f"{selector} matches more than one installed runtime")
        if not matches:
            raise ManagerError("not_found", f"runtime {selector} is not installed",
                               hint=f"lsdtools runtime install {selector}")
        return self._verified(self._row_of(matches[0]), depth) if depth > Verify.ROW else matches[0]

    def _row_of(self, installation: Installation) -> dict:
        return {"coordinate": installation.coordinate, "manifest_sha256": installation.manifest_sha256,
                "manifest_signature": installation.signature}

    # -- the store's own files ------------------------------------------------------------------

    def require_store_file(self, *, create: bool) -> None:
        """store-v1.json names this target and platform; a store with a ledger but no store file is adopted
        only when every row verifies."""
        path = long_path(self.root / STORE_FILE)
        expected = {"schema_version": 1, "target": self.target.name, "platform": self.system, "arch": self.arch}
        if os.path.lexists(path):
            with open(path, "rb") as handle:
                found = strict_loads(handle.read(4097), maximum=4096, label=STORE_FILE)
            if found != expected:
                raise ManagerError("trust", f"{self.root} is a store for {found.get('target')} "
                                   f"{found.get('platform')}-{found.get('arch')}, not {self.target.name} "
                                   f"{self.system}-{self.arch}", hint="pass the matching --target, or another --home")
            return
        if not create:
            return
        if self._ledger():
            self.installations(Verify.ROW)  # a ledger without a store file: every row must verify first
        os.makedirs(long_path(self.root), exist_ok=True)
        _write_atomic(self.root / STORE_FILE, canonical_bytes(expected))

    def default(self, depth: Verify = Verify.ROW) -> Installation | None:
        path = long_path(self.root / DEFAULT_FILE)
        if not os.path.lexists(path):
            installed = self.installations(depth)
            return installed[0] if installed else None
        with open(path, "rb") as handle:
            pointer = strict_loads(handle.read(4097), maximum=4096, label=DEFAULT_FILE)
        coordinate = pointer.get("coordinate") if type(pointer) is dict else None
        for row in self._ledger():
            if row.get("coordinate") == coordinate:
                return self._verified(row, depth)
        installed = self.installations(depth)  # the default was removed: the newest is the default now
        return installed[0] if installed else None

    def set_default(self, installation: Installation) -> None:
        _write_atomic(self.root / DEFAULT_FILE,
                      canonical_bytes({"schema_version": 1, "coordinate": installation.coordinate}))

    def _replace_ledger(self, change: Callable[[list[dict]], list[dict]]) -> None:
        rows = change(list(self._ledger()))
        if rows:
            _write_atomic(self.root / LEDGER, canonical_bytes({"schema_version": 1, "installations": rows}))
        elif os.path.lexists(long_path(self.root / LEDGER)):
            os.remove(long_path(self.root / LEDGER))

    # -- installing ------------------------------------------------------------------------------

    def _download(self, transport: Transport, row: CatalogRow, progress) -> Path:
        """The signed artifact's bytes: from the target's mirrors first (GitHub Releases), else its origin.

        Every source is held to the signed manifest's exact size and sha256; a mirror that is missing, slow or
        wrong only moves the download on. Each source resumes its own ``.part`` file."""
        downloads = self.root / "downloads"
        os.makedirs(long_path(downloads), exist_ok=True)
        sha256 = row.coordinate["artifact_sha256"]
        size = row.manifest["archive_size"]
        label = f"{row.product} {row.coordinate['version']}"
        report = None if progress is None else lambda have, total: progress(label, have, total)
        for template in self.target.artifact_mirrors:
            try:
                return transport.download_mirror(mirror_url(template, row.coordinate), downloads / f"{sha256}.mirror.part",
                                                 size=size, sha256=sha256, progress=report)
            except ManagerError:
                continue  # the origin serves the same signed bytes
        return transport.download(row.url, downloads / f"{sha256}.part", size=size, sha256=sha256, progress=report)

    def _base_root(self, coordinate: dict) -> Path:
        return self.root / "bases" / coordinate["version"] / coordinate["release_id"] / coordinate["artifact_sha256"]

    def _base_index(self, row: CatalogRow, root: Path) -> tuple | None:
        """The Base's members-v1.json index, if it reproduces the signed tree digest."""
        path = long_path(root / BASE_INDEX)
        if not _plain(path, directory=False):
            return None
        with open(path, "rb") as handle:
            raw = handle.read(_MAX_INDEX + 1)
        try:
            document = strict_loads(raw, maximum=_MAX_INDEX, label=BASE_INDEX)
        except ManagerError:
            return None
        records = document.get("members") if type(document) is dict and document.get("schema_version") == 1 else None
        if type(records) is not list or not records:
            return None
        index = []
        for record in records:
            if not (type(record) is list and len(record) == 3 and type(record[0]) is str and (
                    record[1:] == [None, None] or (type(record[1]) is int and record[1] >= 0
                                                   and type(record[2]) is str and _SHA256.fullmatch(record[2])))):
                return None
            index.append(tuple(record))
        return tuple(index) if index_sha256(index) == row.manifest["tree_sha256"] else None

    @staticmethod
    def _index_bytes(index) -> bytes:
        return canonical_bytes({"schema_version": 1, "members": [list(record) for record in index]})

    def _cached_base(self, row: CatalogRow) -> tuple[Path, tuple] | None:
        """The cached Base's payload and member index, if its receipt is this row's exact bytes. A Base
        without a valid index (damaged, or never written) is indexed by reading it once, and must be its signed tree."""
        root = self._base_root(row.coordinate)
        receipt = long_path(root / BASE_RECEIPT)
        payload = long_path(root / "payload")
        if not (_plain(receipt, directory=False) and _plain(payload, directory=True)):
            return None
        with open(receipt, "rb") as handle:
            if handle.read(_MAX_MANIFEST + 1) != self._base_receipt(row):
                return None
        if sorted(os.listdir(payload)) != ["dependencies", "python"]:
            return None
        index = self._base_index(row, root)
        if index is None:
            records: list = []
            if tree_sha256(root / "payload", index=records) != row.manifest["tree_sha256"]:
                return None
            index = tuple(records)
            _write_atomic(root / BASE_INDEX, self._index_bytes(index))
        return root / "payload", index

    @staticmethod
    def _base_receipt(row: CatalogRow) -> bytes:
        return canonical_bytes({"manifest": row.manifest, "manifest_signature": row.signature, "schema_version": 1})

    def _install_base(self, transport: Transport, row: CatalogRow, progress, *, replace: bool) -> tuple[Path, tuple]:
        check_base_manifest(row.manifest, self.system, self.arch, self.platform)
        root = self._base_root(row.coordinate)
        os.makedirs(long_path(root.parent), exist_ok=True)
        archive_path = self._download(transport, row, progress)
        staging = root.parent / f".{row.coordinate['artifact_sha256']}.{os.urandom(6).hex()}.staging"
        try:
            os.mkdir(long_path(staging))
            extracted = extract(archive_path, staging / "payload", profile="base")
            if extracted.tree_sha256 != row.manifest["tree_sha256"]:
                raise ManagerError("trust", f"Base {row.coordinate['version']}'s files are not its signed tree")
            with open(long_path(staging / BASE_RECEIPT), "wb") as handle:
                handle.write(self._base_receipt(row))
            with open(long_path(staging / BASE_INDEX), "wb") as handle:
                handle.write(self._index_bytes(extracted.index))
            self._publish(staging, root, replace=replace)
        finally:
            _remove_tree(long_path(staging))
        os.remove(long_path(archive_path))
        return root / "payload", extracted.index

    def _publish(self, staging: Path, final: Path, *, replace: bool) -> None:
        """Rename ``staging`` to ``final``; with ``replace``, swap out the damaged tree there first."""
        if replace and os.path.lexists(long_path(final)):
            retired = final.parent / f".{final.name}.{os.urandom(6).hex()}.retired"
            os.rename(long_path(final), long_path(retired))
            try:
                os.rename(long_path(staging), long_path(final))
            except OSError:
                os.rename(long_path(retired), long_path(final))
                raise
            _remove_tree(long_path(retired))
            return
        os.rename(long_path(staging), long_path(final))

    def _materialize(self, base: Path, staging: Path, index: tuple) -> None:
        """Create exactly the Base's indexed folders and hard-link (else copy, hashing) each indexed file into
        ``staging``: the runtime outlives the cached Base, and nothing the index lacks reaches it."""
        source, target = long_path(base), long_path(staging)
        for path, size, sha in sorted(index, key=lambda record: record[0].encode("ascii")):  # parents first
            if size is None:
                os.mkdir(child(target, path))
                continue
            try:
                os.link(child(source, path), child(target, path))
            except OSError:
                if _copy_hashed(child(source, path), child(target, path)) != (size, sha):
                    raise ManagerError("trust", f"the cached Base's {path} is not its signed file") from None

    def install(self, catalog: Catalog, row: CatalogRow, *, progress=None,
                repair: bool = False) -> tuple[Installation, bool]:
        """Install ``row`` (and its Base); return it verified, and whether anything was written.

        Every byte is hashed as it is written, and the signed payload digest is computed from the Base's
        index and the delta's digests, so an install never reads its tree back for its digest (on Windows, a
        new file's first read is a malware scan). It does read its executable files once, the Base's while the
        Desktop downloads, so that the scan happens here rather than at the first launch
        (:func:`_read_executables`). Its signature, executables and app bundle are then checked
        (``Verify.SIGNED``), and every file and folder gets one modification time.
        An installed runtime is re-checked to that depth; ``repair`` re-reads every file instead, and
        reinstalls a damaged runtime and Base from fresh archives.
        """
        coordinate = row.coordinate
        for installed in self._ledger():
            if installed.get("coordinate") == coordinate:
                if installed.get("manifest_sha256") != sha256_bytes(row.manifest_bytes):
                    raise ManagerError("trust", f"runtime {coordinate['version']} is ledgered with another manifest")
                try:
                    return self._verified(installed, Verify.FULL if repair else Verify.SIGNED), False
                except ManagerError:
                    break  # its files are damaged: repair them from a fresh archive below
        final = self.root / "versions" / coordinate["version"] / coordinate["artifact_sha256"]
        row_json = {"coordinate": coordinate, "manifest_sha256": sha256_bytes(row.manifest_bytes),
                    "manifest_signature": row.signature}
        if os.path.lexists(long_path(final)):
            try:  # the one crash state: published, not yet ledgered; adopt it only if it verifies in full
                with open(long_path(final / MANIFEST_NAME), "rb") as handle:
                    if handle.read(_MAX_MANIFEST + 1) == row.manifest_bytes:
                        self._ledger_add(row_json)
                        return self._verified(row_json, Verify.FULL), True
            except (OSError, ManagerError):
                pass  # damaged or foreign: replaced from a fresh archive below -- never fatal
        base_row = catalog.base_for(row)
        cached = None if repair else self._cached_base(base_row)
        base, index = cached or self._install_base(catalog.transport, base_row, progress, replace=True)
        base_read = _in_background(_read_executables, long_path(base))  # beside the Desktop's download
        os.makedirs(long_path(final.parent), exist_ok=True)
        archive_path = self._download(catalog.transport, row, progress)
        staging = final.parent / f".{coordinate['artifact_sha256']}.{os.urandom(6).hex()}.staging"
        try:
            os.mkdir(long_path(staging))
            self._materialize(base, staging, index)
            extracted = extract(archive_path, staging, profile="delta")
            manifest = row.manifest
            expected = {"LSDDesktop.exe": manifest["desktop_executable_sha256"],
                        "LSDCli.exe": manifest["cli_executable_sha256"],
                        "bundles/app.pak": manifest["app_bundle_sha256"]}
            if extracted.tree_sha256 != manifest["archive_tree_sha256"] or extracted.critical != expected:
                raise ManagerError("trust", f"Desktop {coordinate['version']}'s archive is not its signed tree")
            if index_sha256(index + extracted.index) != manifest["payload_tree_sha256"]:
                raise ManagerError("trust", f"Desktop {coordinate['version']} over Base "
                                   f"{base_row.coordinate['version']} is not the signed tree")
            with open(long_path(staging / MANIFEST_NAME), "wb") as handle:
                handle.write(row.manifest_bytes)
            _settle_times(long_path(staging), time.time())  # no folder newer than a cache inside it
            self._publish(staging, final, replace=os.path.lexists(long_path(final)))
        finally:
            _remove_tree(long_path(staging))
        try:
            base_read.result()
            _read_executables(long_path(final))  # the Desktop's own, and any Base file copied rather than linked
            self._ledger_add(row_json)
            installation = self._verified(row_json, Verify.SIGNED)
        except BaseException:
            if not any(r.get("coordinate") == coordinate for r in self._ledger()):
                _remove_tree(long_path(final))  # never leave a tree the ledger does not name
            raise
        os.remove(long_path(archive_path))
        return installation, True

    def _ledger_add(self, row_json: dict) -> None:
        self._replace_ledger(lambda rows: rows if any(r.get("coordinate") == row_json["coordinate"] for r in rows)
                             else rows + [row_json])

    # -- removing --------------------------------------------------------------------------------

    def remove(self, installation: Installation) -> bool:
        """Remove one runtime: refused (``in_use``) while a process runs an executable from it. Return
        False if a process that started since left files only ``gc`` can delete later."""
        final = installation.root
        retired = final.parent / f".{final.name}.{os.urandom(6).hex()}.retired"
        running = _processes_under(final)
        if running:
            raise ManagerError("in_use", f"runtime {installation.selector} is running (process "
                               f"{', '.join(str(pid) for pid in running[:5])})", hint="close it first")
        try:
            os.rename(long_path(final), long_path(retired))
        except OSError as exc:
            raise ManagerError("in_use", f"runtime {installation.selector} could not be moved aside: {exc}",
                               hint="close every LSD window and command, then retry") from None
        try:
            self._replace_ledger(lambda rows: [r for r in rows if r.get("coordinate") != installation.coordinate])
        except BaseException:
            os.rename(long_path(retired), long_path(final))  # still ledgered: it keeps its files
            raise
        try:
            _remove_tree(long_path(retired))
            complete = True
        except OSError:
            complete = False  # a process started meanwhile holds a file; the retired tree is gc's -- never fatal
        pointer = long_path(self.root / DEFAULT_FILE)
        if os.path.lexists(pointer):
            with open(pointer, "rb") as handle:
                default = strict_loads(handle.read(4097), maximum=4096, label=DEFAULT_FILE)
            if type(default) is dict and default.get("coordinate") == installation.coordinate:
                os.remove(pointer)
        return complete

    def gc(self) -> int:
        """Remove debris, downloads and Bases no runtime is built over; return the bytes freed."""
        installed = self.installations(Verify.ROW)
        keep = {tuple(item.manifest["runtime_base"][k] for k in ("version", "release_id", "artifact_sha256"))
                for item in installed}
        freed = 0
        doomed: list[str] = []
        for folder in ("downloads",):
            path = long_path(self.root / folder)
            if os.path.isdir(path):
                doomed.extend(child(path, name) for name in os.listdir(path))
        for path in self._walk_bases():
            version, release, sha = path.split("\\" if WINDOWS else "/")[-3:]
            if (version, release, sha) not in keep:
                doomed.append(path)
        for parent in (self.root / "versions", self.root / "bases"):
            for path in _debris(long_path(parent)):
                doomed.append(path)
        for path in doomed:
            freed += _size(path)
            if os.path.isdir(path):
                _remove_tree(path)
            else:
                os.remove(path)
        return freed

    def _walk_bases(self) -> Iterable[str]:
        bases = long_path(self.root / "bases")
        if not os.path.isdir(bases):
            return
        for version in os.listdir(bases):
            for release in os.listdir(child(bases, version)):
                for sha in os.listdir(child(bases, f"{version}/{release}")):
                    if not sha.startswith("."):
                        yield child(bases, f"{version}/{release}/{sha}")


def _debris(parent: str) -> Iterable[str]:
    """Staging and retired folders: one level below ``versions/<v>/`` and two below ``bases/<v>/``."""
    if not os.path.isdir(parent):
        return
    pending = [(parent, 0)]
    while pending:
        folder, depth = pending.pop()
        with os.scandir(folder) as entries:
            for entry in entries:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                path = child(folder, entry.name)
                if _DEBRIS.fullmatch(entry.name):
                    yield path
                elif depth < 2 and not entry.name.startswith("."):
                    pending.append((path, depth + 1))


def _size(path: str) -> int:
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    pending = [path]
    while pending:
        folder = pending.pop()
        with os.scandir(folder) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(child(folder, entry.name))
                else:
                    total += entry.stat(follow_symlinks=False).st_size
    return total


def _processes_under(root: Path) -> list[int]:
    """The ids of processes whose executable lies under ``root`` (Windows: their image paths; Linux:
    /proc/<pid>/exe). Windows lets a folder be renamed while an executable in it runs, so this is the check."""
    if WINDOWS:
        return _windows_processes_under(root)
    prefix = os.path.realpath(root) + os.sep
    found = []
    proc = Path("/proc")
    for entry in proc.iterdir() if proc.is_dir() else ():
        if entry.name.isdigit():
            try:
                if os.path.realpath(entry / "exe").startswith(prefix):
                    found.append(int(entry.name))
            except OSError:
                continue  # the process ended, or is another user's -- never fatal
    return found


def _windows_processes_under(root: Path) -> list[int]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.EnumProcesses.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                    ctypes.POINTER(wintypes.DWORD)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    count = 4096
    while True:
        ids = (wintypes.DWORD * count)()
        used = wintypes.DWORD()
        if not psapi.EnumProcesses(ids, ctypes.sizeof(ids), ctypes.byref(used)):
            raise ManagerError("unavailable", "Windows could not list its processes")
        if used.value < ctypes.sizeof(ids):
            break
        count *= 2
    prefix = os.path.abspath(root).replace("/", "\\").casefold().rstrip("\\") + "\\"
    found = []
    for pid in ids[:used.value // ctypes.sizeof(wintypes.DWORD)]:
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            continue  # gone, or protected: never an LSD runtime of this user's -- never fatal
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buffer))
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                image = buffer.value
                image = image[4:] if image.startswith("\\\\?\\") else image
                if image.casefold().startswith(prefix):
                    found.append(int(pid))
        finally:
            kernel32.CloseHandle(handle)
    return found
