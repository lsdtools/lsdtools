"""This user's ``.lsd`` files and ``lsd://`` links open LSD: per-user associations, no administrator.

They run ``lsdtools-gui`` (the wheel's windowless entry point) with the global options the associations were
registered with: a double-clicked project opens (``lsdtools-gui open FILE``), a link from a web page is
handled (``lsdtools-gui handle-url URL``), and the start menu's LSD opens the start screen. On Windows a
home whose runtime store is its own opens a double-clicked project in its default runtime's Desktop
directly (``desktop``), with no lsdtools process before the window: that runtime belongs to the home
(lsd_packaging.home) and hands a project pinned to another runtime on, and lsdtools re-points the
association whenever the home's default runtime changes.

- Windows: ``HKEY_CURRENT_USER\\Software\\Classes`` (``.lsd`` -> ``LSD.Project``, the ``lsd`` URL
  protocol) and a Start menu shortcut;
- Linux: an XDG desktop entry and MIME type under ``$XDG_DATA_HOME`` (``~/.local/share``), set as the
  default for ``*.lsd`` and ``x-scheme-handler/lsd``;
- macOS: needs an application bundle, which ships with the macOS runtime.

``unregister`` removes exactly what ``register`` writes, and only while it still names an lsdtools-gui or a
Desktop in a runtime store.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .errors import ManagerError

__all__ = ["direct_desktop", "register", "status", "unregister"]

PROG_ID = "LSD.Project"
DESKTOP_ID = "io.lsd.LSD"
MIME_TYPE = "application/x-lsd-project"


def _quoted(argv: list[str]) -> str:
    return subprocess.list2cmdline(argv)


# ── Windows ──────────────────────────────────────────────────────────────────────
class _Registry:
    """The per-user classes root (a test passes its own subkey)."""

    def __init__(self, root: str = r"Software\Classes") -> None:
        import winreg

        self.winreg, self.root = winreg, root

    def set(self, key: str, value: str, name: str = "") -> None:
        with self.winreg.CreateKeyEx(self.winreg.HKEY_CURRENT_USER, f"{self.root}\\{key}", 0,
                                     self.winreg.KEY_SET_VALUE) as handle:
            self.winreg.SetValueEx(handle, name, 0, self.winreg.REG_SZ, value)

    def get(self, key: str, name: str = "") -> str | None:
        try:
            with self.winreg.OpenKey(self.winreg.HKEY_CURRENT_USER, f"{self.root}\\{key}") as handle:
                return str(self.winreg.QueryValueEx(handle, name)[0])
        except OSError:
            return None

    def delete_tree(self, key: str) -> None:
        """Delete *key* and everything below it; ``""`` is the root itself (a test's own subkey)."""
        path = f"{self.root}\\{key}" if key else self.root
        try:
            with self.winreg.OpenKey(self.winreg.HKEY_CURRENT_USER, path, 0,
                                     self.winreg.KEY_READ | self.winreg.KEY_WRITE) as handle:
                children = []
                index = 0
                while True:
                    try:
                        children.append(self.winreg.EnumKey(handle, index))
                    except OSError:
                        break
                    index += 1
            for child in children:
                self.delete_tree(f"{key}\\{child}" if key else child)
            self.winreg.DeleteKey(self.winreg.HKEY_CURRENT_USER, path)
        except FileNotFoundError:
            pass  # nothing registered there -- never fatal


def _start_menu_shortcut() -> Path:
    return Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "LSD.lnk"


def _windows_register(gui: list[str], registry: _Registry, *, shortcut: bool, desktop: str | None) -> dict:
    registry.set(".lsd", PROG_ID)
    registry.set(PROG_ID, "LSD project")
    registry.set(f"{PROG_ID}\\DefaultIcon", f"{_quoted([desktop or gui[0]])},0")
    # One argument after a runtime's Desktop: its launcher reads a positional project as one opaque payload.
    opens = _quoted([desktop]) if desktop else _quoted([*gui, "open"])
    registry.set(f"{PROG_ID}\\shell\\open\\command", opens + ' "%1"')
    written = {"files": ".lsd", "links": "lsd://", "opens": desktop or "lsdtools-gui"}
    registry.set("lsd", "URL:LSD")
    registry.set("lsd", "", "URL Protocol")
    registry.set("lsd\\shell\\open\\command", _quoted([*gui, "handle-url"]) + ' "%1"')
    if shortcut:
        path = _start_menu_shortcut()
        path.parent.mkdir(parents=True, exist_ok=True)
        # The Shell's own COM object writes .lnk files. Its values reach the script through the child's
        # environment, never its command text, so no path is ever parsed as PowerShell.
        script = ("$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:SHORTCUT_PATH); "
                  "$s.TargetPath = $env:SHORTCUT_TARGET; $s.Arguments = $env:SHORTCUT_ARGUMENTS; "
                  "$s.Description = 'LSD'; $s.Save()")
        environment = {**os.environ, "SHORTCUT_PATH": str(path), "SHORTCUT_TARGET": gui[0],
                       "SHORTCUT_ARGUMENTS": _quoted(gui[1:])}
        done = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                              env=environment, capture_output=True, timeout=60)
        if done.returncode != 0 or not path.is_file():
            raise ManagerError("unavailable", "Windows could not write the Start menu shortcut: "
                               + done.stderr.decode("utf-8", "replace").strip()[-400:])
        written["shortcut"] = str(path)
    _windows_changed()
    return written


def _ours(command: str | None) -> bool:
    """An lsdtools-gui command, or the Desktop of a runtime store (``...\\runtime\\versions\\...\\LSDDesktop.exe``)."""
    if command is None:
        return False
    text = command.lower().replace("/", "\\")
    return "lsdtools-gui" in text or ("\\runtime\\versions\\" in text and "lsddesktop.exe" in text)


def direct_desktop(registry: _Registry | None = None) -> str | None:
    """The runtime Desktop a double-clicked project opens in directly now, or None (lsdtools-gui, or nothing)."""
    if _platform() != "windows":
        return None
    command = (registry or _Registry()).get(f"{PROG_ID}\\shell\\open\\command") or ""
    if not _ours(command) or "lsdtools-gui" in command.lower():
        return None
    return command.rsplit(' "%1"', 1)[0].strip().strip('"')


def _windows_unregister(registry: _Registry) -> dict:
    removed = []
    if _ours(registry.get(f"{PROG_ID}\\shell\\open\\command")):
        registry.delete_tree(PROG_ID)
        if registry.get(".lsd") == PROG_ID:
            registry.delete_tree(".lsd")
        removed.append(".lsd")
    if _ours(registry.get("lsd\\shell\\open\\command")):
        registry.delete_tree("lsd")
        removed.append("lsd://")
    shortcut = _start_menu_shortcut()
    if shortcut.is_file():
        shortcut.unlink()
        removed.append(str(shortcut))
    _windows_changed()
    return {"removed": removed}


def _windows_changed() -> None:
    import ctypes

    ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)  # SHCNE_ASSOCCHANGED


# ── Linux (XDG) ──────────────────────────────────────────────────────────────────
def _data_home() -> Path:
    value = os.environ.get("XDG_DATA_HOME", "")
    return Path(value) if os.path.isabs(value) else Path.home() / ".local" / "share"


def _linux_files() -> tuple[Path, Path]:
    data = _data_home()
    return data / "applications" / f"{DESKTOP_ID}.desktop", data / "mime" / "packages" / f"{DESKTOP_ID}.xml"


def _linux_register(gui: list[str]) -> dict:
    entry, mime = _linux_files()
    exec_line = " ".join(_desktop_quoted(part) for part in gui) + " %u"
    entry.parent.mkdir(parents=True, exist_ok=True)
    mime.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text("[Desktop Entry]\nType=Application\nName=LSD\nComment=Visual data pipelines\n"
                     f"Exec={exec_line}\nMimeType={MIME_TYPE};x-scheme-handler/lsd;\nTerminal=false\n"
                     "Categories=Development;Science;\n", encoding="utf-8")
    mime.write_text('<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">\n'
                    f'  <mime-type type="{MIME_TYPE}">\n    <comment>LSD project</comment>\n'
                    '    <glob pattern="*.lsd"/>\n  </mime-type>\n</mime-info>\n', encoding="utf-8")
    ran = _xdg_refresh()
    for tool, argv in (("xdg-mime", ["xdg-mime", "default", entry.name, MIME_TYPE, "x-scheme-handler/lsd"]),):
        if shutil.which(tool):
            subprocess.run(argv, check=False, capture_output=True, timeout=60)
            ran.append(tool)
    return {"files": ".lsd", "links": "lsd://", "desktop_entry": str(entry), "refreshed": ran}


def _desktop_quoted(part: str) -> str:
    """One Exec= argument, quoted as the Desktop Entry Specification asks."""
    if part and all(ch.isalnum() or ch in "/._-+=:@" for ch in part):
        return part
    escaped = "".join("\\" + ch if ch in '"`$\\' else ch for ch in part)
    return f'"{escaped}"'


def _xdg_refresh() -> list[str]:
    entry, _mime = _linux_files()
    ran = []
    for tool, argv in (("update-mime-database", ["update-mime-database", str(_data_home() / "mime")]),
                       ("update-desktop-database", ["update-desktop-database", str(entry.parent)])):
        if shutil.which(tool):
            subprocess.run(argv, check=False, capture_output=True, timeout=60)
            ran.append(tool)
    return ran


def _linux_unregister() -> dict:
    removed = []
    for path in _linux_files():
        if path.is_file() and (path.suffix == ".xml" or "lsdtools-gui" in path.read_text("utf-8", "replace")):
            path.unlink()
            removed.append(str(path))
    _xdg_refresh()
    return {"removed": removed}


# ── the commands ─────────────────────────────────────────────────────────────────
def _platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    raise ManagerError("platform_unavailable", "file and link handlers on macOS come with its application bundle")


def register(gui: list[str], *, desktop: str | None = None, shortcut: bool = True,
             registry: _Registry | None = None) -> dict:
    """Associate ``.lsd`` and ``lsd://`` with *gui* (``lsdtools-gui`` and its global options); on Windows,
    ``.lsd`` with *desktop*, the home's default runtime's Desktop, when given."""
    if _platform() == "windows":
        return _windows_register(gui, registry or _Registry(), shortcut=shortcut, desktop=desktop)
    return _linux_register(gui)


def unregister(*, registry: _Registry | None = None) -> dict:
    if _platform() == "windows":
        return _windows_unregister(registry or _Registry())
    return _linux_unregister()


def status(*, registry: _Registry | None = None) -> dict:
    """What opens ``.lsd`` files and ``lsd://`` links for this user now."""
    if _platform() == "windows":
        registry = registry or _Registry()
        return {"files": registry.get(f"{PROG_ID}\\shell\\open\\command"),
                "links": registry.get("lsd\\shell\\open\\command")}
    entry, _mime = _linux_files()
    return {"desktop_entry": str(entry) if entry.is_file() else None}
