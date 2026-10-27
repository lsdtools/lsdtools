"""Start one of a verified runtime's executables, with the environment every LSD launcher gives a child.

The child's environment drops the interpreter, toolkit and TLS overrides of the caller's (``PYTHON*``,
``GTK_*``, ``SSL_CERT_FILE``, ``MSYSTEM``, ...) and every ``LSD_*`` variable, then sets ``LSD_HOME``, the
runtime's own ``PATH`` and its exact coordinate (``LSD_DESKTOP_RUNTIME_COORDINATE_V1``, a launch
assertion the child checks against its own signed row). The caller finds the runtime first; it was
verified when installed (``Store.find(..., Verify.ROW)``).

An attached child (a CLI command) runs in a Windows job object that kills it and its children when this
process ends; on POSIX this process becomes the child (``execve``). The job permits breakaway: a window or
a Project Host the command starts leaves it (``lsd_platform.runtime_launch``), so the window ``open``
started outlives the command. A detached child (a Desktop window) outlives this process.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from .canonical import canonical_bytes
from .errors import ManagerError
from .paths import WINDOWS
from .store import Installation

__all__ = ["Job", "child_environment", "run_attached", "run_result", "start_detached"]

_OWNED = frozenset({
    "PATH", "MSYSTEM", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE", "OPENSSL_CONF", "OPENSSL_MODULES",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
})
_LOADER_PREFIXES = ("PYTHON", "GTK_", "GDK_", "GSK_", "GI_", "GIO_", "GSETTINGS_", "PANGO_", "FONTCONFIG_",
                    "XDG_", "LSD_")
_COORDINATE = "LSD_DESKTOP_RUNTIME_COORDINATE_V1"


def _owned(name: str) -> bool:
    upper = name.upper()
    return upper in _OWNED or upper.startswith(_LOADER_PREFIXES)


def child_environment(installation: Installation, home: Path, extra: dict | None = None) -> dict[str, str]:
    environment = {name: value for name, value in os.environ.items() if not _owned(name)}
    root = installation.root
    if WINDOWS:
        system = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or "C:\\Windows"
        folders = [root / "dependencies" / "bin", root, root / "python", Path(system) / "System32", Path(system)]
        environment["PATH"] = ";".join(os.path.normpath(str(folder)).replace("/", "\\") for folder in folders)
    else:
        folders = [root / "bin", root / "dependencies" / "bin", "/usr/bin", "/bin"]
        environment["PATH"] = ":".join(str(folder) for folder in folders)
    environment["LSD_HOME"] = str(home)
    environment[_COORDINATE] = canonical_bytes(installation.coordinate).decode("ascii")
    for name, value in (extra or {}).items():
        if not name or "=" in name or "\0" in value:
            raise ManagerError("internal", f"invalid child environment entry {name!r}")
        environment[name] = value
    return environment


class Job:
    """A Windows job object whose processes die when it closes, as it does when this process ends.

    With ``breakaway`` a process that a member starts may leave it (``CREATE_BREAKAWAY_FROM_JOB``): the window
    a command opens does. Without it no process leaves, and ``active`` counts every process the run started.
    ``start`` puts a process in the job before it runs a single instruction, so nothing it starts escapes."""

    def __init__(self, *, breakaway: bool) -> None:
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("ReadOperationCount", "WriteOperationCount",
                        "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                                     wintypes.DWORD]
        kernel32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                                       wintypes.DWORD, wintypes.LPVOID]
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32 = kernel32
        self.handle = kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise ManagerError("unavailable", "Windows could not create a job object for the runtime")
        limits = ExtendedLimits()
        # KILL_ON_JOB_CLOSE, and BREAKAWAY_OK when a member's own launches may leave
        limits.BasicLimitInformation.LimitFlags = 0x2000 | (0x800 if breakaway else 0)
        if not kernel32.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise ManagerError("unavailable", "Windows could not configure the runtime's job object")

    def start(self, arguments: list[str], **options) -> subprocess.Popen:
        """Start ``arguments`` suspended, put the process in this job, then let it run."""
        flags = options.pop("creationflags", 0) | 0x00000004  # CREATE_SUSPENDED
        process = subprocess.Popen(arguments, creationflags=flags, **options)
        try:
            if not self._kernel32.AssignProcessToJobObject(self.handle, int(process._handle)):
                raise ManagerError("unavailable", "Windows could not put the runtime's process in its job")
            _resume_first_thread(process.pid)
        except BaseException:
            process.kill()
            process.wait()
            raise
        return process

    def active(self) -> int:
        """How many of the job's processes are still running."""
        import ctypes
        from ctypes import wintypes

        class Accounting(ctypes.Structure):
            _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
                        ("ThisPeriodTotalUserTime", ctypes.c_int64), ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                        ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
                        ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD)]

        accounting = Accounting()
        if not self._kernel32.QueryInformationJobObject(self.handle, 1, ctypes.byref(accounting),
                                                        ctypes.sizeof(accounting), None):
            raise ManagerError("unavailable", "Windows could not account for the runtime's job")
        return int(accounting.ActiveProcesses)

    def terminate(self) -> None:
        self._kernel32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if self.handle:
            self._kernel32.CloseHandle(self.handle)
            self.handle = None


def _resume_first_thread(process_id: int) -> None:
    """Resume the one thread of a process created suspended (``subprocess`` keeps no thread handle)."""
    import ctypes
    from ctypes import wintypes

    class ThreadEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ThreadID", wintypes.DWORD),
                    ("th32OwnerProcessID", wintypes.DWORD), ("tpBasePri", wintypes.LONG),
                    ("tpDeltaPri", wintypes.LONG), ("dwFlags", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
    if not snapshot or snapshot == wintypes.HANDLE(-1).value:
        raise ManagerError("unavailable", "Windows could not list the runtime process's threads")
    try:
        entry = ThreadEntry()
        entry.dwSize = ctypes.sizeof(entry)
        present = kernel32.Thread32First(snapshot, ctypes.byref(entry))
        while present:
            if entry.th32OwnerProcessID == process_id:
                thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)  # THREAD_SUSPEND_RESUME
                if not thread:
                    break
                try:
                    if kernel32.ResumeThread(thread) == 0xFFFFFFFF:
                        break
                    return
                finally:
                    kernel32.CloseHandle(thread)
            present = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    raise ManagerError("unavailable", f"Windows could not start the runtime process {process_id}")


def run_attached(installation: Installation, which: str, arguments: list[str], *, home: Path,
                 extra: dict | None = None, cwd: str | None = None) -> int:
    """Run ``<runtime>/<executable> arguments`` with this console and return its exit status."""
    executable = str(installation.executable(which))
    environment = child_environment(installation, home, extra)
    if not WINDOWS:
        sys.stdout.flush()
        sys.stderr.flush()
        if cwd:
            os.chdir(cwd)
        os.execve(executable, [executable, *arguments], environment)
    job = Job(breakaway=True)  # this process's end closes it; the window a command opens leaves it
    import signal

    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)  # the child shares the console and answers Ctrl+C
    try:
        return job.start([executable, *arguments], env=environment, cwd=cwd).wait()
    finally:
        signal.signal(signal.SIGINT, previous)


def run_result(installation: Installation, arguments: list[str], *, home: Path, cwd: str | None = None) -> dict:
    """Run one runtime command (``LSDCli lsdtools --json <arguments>``) as this command's step and return
    its ``lsdtools.result.v1`` document; its progress reaches this process's stderr as it is written."""
    import json

    executable = str(installation.executable("cli"))
    command = [executable, "lsdtools", "--json", *arguments]
    environment = child_environment(installation, home)
    options = {"env": environment, "cwd": cwd, "stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE}
    if WINDOWS:
        job = Job(breakaway=True)
        try:
            process = job.start(command, **options)
            output, _ = process.communicate()
        finally:
            job.close()
    else:
        process = subprocess.Popen(command, **options)
        output, _ = process.communicate()
    lines = output.decode("utf-8", "replace").strip().splitlines()
    try:
        document = json.loads(lines[-1]) if lines else None
    except ValueError:
        document = None
    if type(document) is not dict or document.get("schema") != "lsdtools.result.v1":
        raise ManagerError("protocol", f"the runtime's {arguments[0]} answered no result document "
                                       f"(exit {process.returncode})")
    return document


def start_detached(installation: Installation, which: str, arguments: list[str], *, home: Path,
                   extra: dict | None = None, cwd: str | None = None) -> subprocess.Popen:
    """Start ``<runtime>/<executable> arguments`` on its own (a window, a host) and return its process, which
    outlives this one: out of any job this process runs in, when that job allows it."""
    executable = str(installation.executable(which))
    environment = child_environment(installation, home, extra)
    options: dict = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                     "close_fds": True, "env": environment, "cwd": cwd or str(installation.root)}
    if not WINDOWS:
        return subprocess.Popen([executable, *arguments], start_new_session=True, **options)
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        return subprocess.Popen([executable, *arguments], creationflags=flags | subprocess.CREATE_BREAKAWAY_FROM_JOB,
                                **options)
    except PermissionError:
        # This process's job forbids breakaway (a CI runner's, a service's): the window stays in it.
        return subprocess.Popen([executable, *arguments], creationflags=flags, **options)
