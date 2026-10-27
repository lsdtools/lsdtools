"""``lsdtools verify``: the exact-runtime release check, run by lsdtools from outside the runtime it checks.

One installed runtime is proven on this machine end to end (runtime-store-v1 ``verify``). Its integrity
model is ``quiescent-user-store-v1``: race-detecting evidence on a quiet machine, never a sandbox. The
runtime's files belong to this user, and another of this user's processes can still interfere with a run;
the run fails when its guards or its final hash see that happen, and never claims to prevent it.

1. The ledger row, the manifest's signature and the executables (``Verify.SIGNED``), and the private
   verifier closure against ``verifier/verifier-manifest-v1.json``, whose runtime identity must be this
   installation's.
2. Guards for the whole run: every member held open deny-write and deny-delete, and a change notification
   armed on the tree. Then the whole tree is hashed against its signed digest.
3. A fresh verifier home in the temporary directory, the fixture (or, without one, a blank project the
   runtime creates) copied to ``work/projects/exact-runtime-probe.lsd`` and pinned to this runtime by the
   runtime's own ``project pin --replace``.
4. In one job object that no process can leave: the Project Host and the Desktop participant (given a
   private action token), both direct children of this process, then the runtime's CLI running the
   verifier's bootstrap with the launcher envelope (``LSD_VERIFIER_*``, the bootstrap's grammar).
5. Success only when the verifier exited 0, the Desktop and the host exited, the job is empty, the guards
   saw no change, and a final hash of the whole tree still matches.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .archive import portable_path, tree_sha256
from .canonical import canonical_bytes, sha256_file, strict_loads
from .errors import ManagerError
from .launch import Job, child_environment
from .paths import WINDOWS, child, long_path

__all__ = ["INTEGRITY_MODEL", "verifier_manifest", "verify_runtime"]

INTEGRITY_MODEL = "quiescent-user-store-v1"
VERIFIER_MANIFEST = "verifier-manifest-v1.json"
_REQUIRED = ("bootstrap.py", "python/lsd_release_verifier/__init__.py", "python/lsd_release_verifier/inventory.py",
             "python/lsd_release_verifier/selftest.py", "python/lsd_release_verifier/workflow.py")
_MAX_MANIFEST = 1 << 20
_MAX_FILES = 1024
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_SHA256 = re.compile(r"[0-9a-f]{64}")
VERIFIER_TIMEOUT_S = 30 * 60.0
EXIT_TIMEOUT_S = 30.0
PROBE = "exact-runtime-probe.lsd"


def _untrusted(message: str) -> ManagerError:
    return ManagerError("trust", f"the release verifier {message}")


def verifier_manifest(installation) -> dict:
    """The runtime's private verifier closure, checked file by file against its manifest, which names this runtime."""
    base = long_path(installation.root / "verifier")
    try:
        with open(child(base, VERIFIER_MANIFEST), "rb") as handle:
            raw = handle.read(_MAX_MANIFEST + 1)
    except FileNotFoundError:
        raise ManagerError("component_missing", f"runtime {installation.selector} has no release verifier") from None
    manifest = strict_loads(raw, maximum=_MAX_MANIFEST, label=VERIFIER_MANIFEST)
    if raw != canonical_bytes(manifest) + b"\n":
        raise _untrusted("manifest is not canonical JSON v1")
    if (type(manifest) is not dict
            or set(manifest) != {"schema_version", "kind", "verifier_version", "entrypoint", "files", "runtime"}
            or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
            or manifest["kind"] != "lsd-installed-release-verifier" or manifest["entrypoint"] != "bootstrap.py"
            or type(manifest["verifier_version"]) is not str or not _VERSION.fullmatch(manifest["verifier_version"])):
        raise _untrusted("manifest's schema is invalid")
    coordinate = installation.coordinate
    expected = {"product": "desktop", "platform": coordinate["platform"], "arch": coordinate["arch"],
                "release_mode": "reserved", "version": coordinate["version"], "release_id": coordinate["release_id"],
                "cli_executable_sha256": installation.manifest["cli_executable_sha256"],
                "app_bundle_sha256": installation.manifest["app_bundle_sha256"]}
    runtime = manifest["runtime"]
    if (type(runtime) is not dict or set(runtime) != {*expected, "build_id"}
            or any(runtime[key] != value for key, value in expected.items())
            or type(runtime["build_id"]) is not str or not runtime["build_id"]):
        raise _untrusted("targets another runtime identity")
    files = manifest["files"]
    if type(files) is not dict or not files or len(files) > _MAX_FILES:
        raise _untrusted("file inventory violates its bound")
    for relative, digest in files.items():
        try:
            portable_path(relative)
        except ManagerError:
            raise _untrusted(f"names an unsafe path {relative!r}") from None
        if relative == VERIFIER_MANIFEST or type(digest) is not str or not _SHA256.fullmatch(digest):
            raise _untrusted("file inventory is invalid")
        try:
            actual = sha256_file(child(base, relative))
        except FileNotFoundError:
            raise _untrusted(f"lacks its {relative}") from None
        if actual != digest:
            raise _untrusted(f"{relative} is not the file its manifest names")
    missing = [name for name in _REQUIRED if name not in files]
    if missing:
        raise _untrusted(f"lacks its private closure: {', '.join(missing)}")
    present, pending = set(), [""]
    while pending:
        relative = pending.pop()
        with os.scandir(child(base, relative)) as entries:
            for entry in entries:
                path = f"{relative}/{entry.name}" if relative else entry.name
                if entry.is_symlink() or (WINDOWS and entry.stat(follow_symlinks=False).st_file_attributes & 0x400):
                    raise _untrusted(f"holds a link or reparse point at {path!r}")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                else:
                    present.add(path)
    if present != set(files) | {VERIFIER_MANIFEST}:
        raise _untrusted("folder holds files its manifest does not name")
    return manifest


class Guards:
    """Every member of a tree held open deny-write and deny-delete, and a notification armed on the tree's names.

    Windows refuses another process's write, rename or delete of a held member, so no content can change and
    no name can go; what the handles cannot refuse is a member added, which signals the notification
    (``changed``). Only names are watched: listing a folder while one of its files is held makes NTFS refresh
    that folder's index, which Windows reports as a last-write change though no byte changed. The final hash
    of the whole tree proves the content."""

    def __init__(self, root: Path) -> None:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                         wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel32.FindFirstChangeNotificationW.restype = wintypes.HANDLE
        kernel32.FindFirstChangeNotificationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
        kernel32.FindCloseChangeNotification.argtypes = [wintypes.HANDLE]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32 = kernel32
        self._invalid = wintypes.HANDLE(-1).value
        self._handles: list[int] = []
        self.members = 0
        base = long_path(root)
        # FILE_NOTIFY_CHANGE_FILE_NAME | DIR_NAME, over the whole subtree
        self._notification = kernel32.FindFirstChangeNotificationW(base, True, 0x1 | 0x2)
        if not self._notification or self._notification == self._invalid:
            self._notification = None
            raise ManagerError("unavailable", f"Windows could not watch {root}")
        try:
            self._hold(base, directory=True)
            pending = [""]
            while pending:
                relative = pending.pop()
                with os.scandir(child(base, relative)) as entries:
                    for entry in entries:
                        path = f"{relative}/{entry.name}" if relative else entry.name
                        directory = entry.is_dir(follow_symlinks=False)
                        self._hold(child(base, path), directory=directory)
                        if directory:
                            pending.append(path)
        except BaseException:
            self.close()
            raise

    def _hold(self, path: str, *, directory: bool) -> None:
        # GENERIC_READ, FILE_SHARE_READ only, OPEN_EXISTING; never through a reparse point
        flags = 0x00200000 | (0x02000000 if directory else 0)  # OPEN_REPARSE_POINT | BACKUP_SEMANTICS
        handle = self._kernel32.CreateFileW(path, 0x80000000, 0x1, None, 3, flags, None)
        if not handle or handle == self._invalid:
            raise ManagerError("trust", f"could not hold {path} against changes (another process has it open "
                               f"for writing: Windows error {self._kernel32_error()})")
        self._handles.append(handle)
        self.members += 1

    @staticmethod
    def _kernel32_error() -> int:
        import ctypes

        return ctypes.get_last_error()

    def changed(self) -> bool:
        return self._notification is not None and self._kernel32.WaitForSingleObject(self._notification, 0) == 0

    def close(self) -> None:
        for handle in self._handles:
            self._kernel32.CloseHandle(handle)
        self._handles.clear()
        if self._notification is not None:
            self._kernel32.FindCloseChangeNotification(self._notification)
            self._notification = None


def _this_image() -> str:
    """This process's executable, as Windows names it (a venv's python.exe starts the base interpreter)."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                    ctypes.POINTER(wintypes.DWORD)]
    buffer = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(buffer))
    if not kernel32.QueryFullProcessImageNameW(kernel32.GetCurrentProcess(), 0, buffer, ctypes.byref(size)):
        raise ManagerError("unavailable", "Windows could not name this process's executable")
    return buffer.value


def _verifier_home() -> Path:
    base = Path(tempfile.gettempdir()) / "lsd-release-verifier"
    base.mkdir(exist_ok=True)
    home = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    for part in ("work", "work/home", "work/projects", "temp"):
        (home / part).mkdir()
    return home


def _exited(process: subprocess.Popen, guards: Guards, seconds: float, what: str) -> int:
    """``process``'s exit status once it exits, failing at once if the guards see the tree change meanwhile."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            return process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            if guards.changed():
                raise ManagerError("trust", "the runtime's files changed while it was being verified") from None
            if time.monotonic() > deadline:
                raise ManagerError("failed", f"{what} did not exit within {seconds:.0f} s") from None


def _empty(job: Job, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while job.active():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)  # job accounting has no wait handle; this reads it until the last process exits
    return True


def _runtime_command(job: Job, installation, home: Path, arguments: list[str], extra: dict) -> dict:
    """One of the runtime's own commands (``LSDCli lsdtools --json ...``), in the verifier's job: its data."""
    from .canonical import strict_loads as loads

    process = job.start([str(installation.executable("cli")), "lsdtools", "--json", *arguments],
                        env=child_environment(installation, home, extra), cwd=str(installation.root),
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = process.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        process.kill()
        raise ManagerError("failed", f"the runtime's {arguments[0]} command did not finish") from None
    lines = out.decode("utf-8", "replace").strip().splitlines()
    try:
        document = loads(lines[-1].encode("utf-8"), maximum=1 << 22, label=arguments[0]) if lines else None
    except ManagerError:
        document = None
    if type(document) is not dict or document.get("schema") != "lsdtools.result.v1":
        raise ManagerError("protocol", f"the runtime answered `lsdtools {arguments[0]}` with no result document "
                           f"(it may predate lsdtools verify): {err.decode('utf-8', 'replace')[-600:]}")
    if not document.get("ok"):
        error = document.get("error") or {}
        raise ManagerError("failed", f"the runtime's {' '.join(arguments[:2])} failed: {error.get('message')}")
    return document["data"]


def _fixture(job: Job, installation, verifier_home: Path, project: str | None, extra: dict) -> tuple[Path, Path]:
    """The fixture's source path, and its copy at the path the verifier reads, pinned to this runtime."""
    child_home = verifier_home / "work" / "home"
    if project:
        source = Path(os.path.abspath(project))
        if source.suffix.casefold() != ".lsd" or not source.is_file():
            raise ManagerError("not_found", f"{project} is not a .lsd project")
    else:
        created = _runtime_command(job, installation, child_home,
                                   ["new", "project", str(verifier_home / "temp" / "blank")], extra)
        source = Path(created["project"])
    target = verifier_home / "work" / "projects" / PROBE
    shutil.copyfile(source, target)
    _runtime_command(job, installation, child_home, ["project", "pin", "--replace", str(target)], extra)
    return source, target


def verify_runtime(store, installation, *, project: str | None = None, reporter=None) -> dict:
    """Run the release check on ``installation`` (verified to ``Verify.SIGNED``); its data, or ManagerError
    with that data when it fails."""
    if not WINDOWS:
        raise ManagerError("platform_unavailable", "lsdtools verify runs on Windows until the Linux runtime")
    note = reporter.note if reporter is not None else (lambda text: None)
    manifest = verifier_manifest(installation)
    expected_tree = installation.manifest["payload_tree_sha256"]
    note(f"holding {installation.root} against changes")
    guards = Guards(installation.root)
    job = None
    data = {"ok": False, "integrity_model": INTEGRITY_MODEL, "runtime": installation.coordinate,
            "verifier_version": manifest["verifier_version"], "members_held": guards.members, "verifier_home": None,
            "process_id": None, "desktop_process_id": None, "host_process_id": None, "exit_code": None,
            "report": None}
    try:
        note("hashing every file of the runtime")
        if tree_sha256(installation.root) != expected_tree:
            raise ManagerError("trust", f"runtime {installation.selector}'s files are not the signed tree",
                               hint=f"lsdtools runtime install {installation.selector} --repair")
        verifier_home = _verifier_home()
        data["verifier_home"] = str(verifier_home)
        child_home = verifier_home / "work" / "home"
        quiet = {"DBUS_SESSION_BUS_ADDRESS": "disabled:", "TEMP": str(verifier_home / "temp"),
                 "TMP": str(verifier_home / "temp"), "PYTHONDONTWRITEBYTECODE": "1"}
        job = Job(breakaway=False)
        source, target = _fixture(job, installation, verifier_home, project, quiet)
        note(f"starting the Project Host and the Desktop on {target.name}")
        desktop_executable = str(installation.executable("desktop"))
        token = secrets.token_hex(32)
        detached = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                    "cwd": str(installation.root)}
        host = job.start([desktop_executable, "--mode", "project-host", str(target), "--stop-when-idle"],
                         env=child_environment(installation, child_home, quiet), **detached)
        data["host_process_id"] = host.pid
        desktop = job.start([desktop_executable, "--mode", "desktop", "--attach", str(target)],
                            env=child_environment(installation, child_home, {
                                **quiet, "LSD_MCP_DESKTOP_TOKEN": token, "LSD_MCP_DESKTOP_PORT": "0"}), **detached)
        data["desktop_process_id"] = desktop.pid
        launcher = _this_image()
        coordinate = installation.coordinate
        arguments = ["verify", str(store.root), str(source), launcher, coordinate["version"],
                     coordinate["release_id"], coordinate["artifact_sha256"]]
        envelope = {**quiet,
                    "LSD_VERIFIER_ROOT": str(installation.root / "verifier"),
                    "LSD_VERIFIER_EXPECTED_CLI": str(installation.executable("cli")),
                    "LSD_VERIFIER_ARGS_JSON": canonical_bytes(arguments).decode("utf-8"),
                    "LSD_VERIFIER_LAUNCHER_PID": str(os.getpid()),
                    "LSD_VERIFIER_LAUNCHER_PATH": launcher,
                    "LSD_VERIFIER_RUNTIME_ROOT": str(installation.root),
                    "LSD_VERIFIER_PROJECT": str(target),
                    "LSD_VERIFIER_DESKTOP_PID": str(desktop.pid),
                    "LSD_VERIFIER_HOST_PID": str(host.pid),
                    "LSD_VERIFIER_ACTION_TOKEN": token}
        note("running the release verifier")
        with open(verifier_home / "verifier.stdout.log", "wb") as out, \
                open(verifier_home / "verifier.stderr.log", "wb") as err:
            verifier = job.start([str(installation.executable("cli")), "dev", "run",
                                  str(installation.root / "verifier" / "bootstrap.py")],
                                 env=child_environment(installation, verifier_home, envelope),
                                 cwd=str(installation.root), stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            data["process_id"] = verifier.pid
            data["exit_code"] = _exited(verifier, guards, VERIFIER_TIMEOUT_S, "the release verifier")
        lines = (verifier_home / "verifier.stdout.log").read_bytes().decode("utf-8", "replace").strip().splitlines()
        try:
            data["report"] = strict_loads(lines[-1].encode("utf-8"), maximum=1 << 22, label="verifier report") \
                if lines else None
        except ManagerError:
            data["report"] = None
        _exited(desktop, guards, EXIT_TIMEOUT_S, "the verifier's Desktop")
        _exited(host, guards, EXIT_TIMEOUT_S, "the verifier's Project Host (after its participant left)")
        if not _empty(job, EXIT_TIMEOUT_S):
            raise ManagerError("failed", "a process the verification started is still running")
        if guards.changed():
            raise ManagerError("trust", "the runtime's files changed while it was being verified")
        note("hashing every file of the runtime again")
        if tree_sha256(installation.root) != expected_tree:
            raise ManagerError("trust", "the runtime's files drifted while it was being verified")
        if guards.changed():
            raise ManagerError("trust", "the runtime's files changed while it was being verified")
        if data["exit_code"] != 0:
            detail = (data["report"] or {}).get("error") if isinstance(data["report"], dict) else None
            raise ManagerError("failed", f"the release verifier reported failure: {detail or 'see its logs'}",
                               hint=f"evidence and logs: {verifier_home}")
        data["ok"] = True
        return data
    except ManagerError as exc:
        raise ManagerError(exc.code, exc.message, hint=exc.hint, retryable=exc.retryable, data=data) from None
    except OSError as exc:
        raise ManagerError("unavailable", f"{type(exc).__name__}: {exc}", data=data) from None
    finally:
        if job is not None:
            if job.active():
                job.terminate()
                _empty(job, EXIT_TIMEOUT_S)
            job.close()
        guards.close()
