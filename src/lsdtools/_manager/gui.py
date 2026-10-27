"""``lsdtools-gui``: the windowless entry point the desktop's file and link associations run.

- ``lsdtools-gui`` opens the start screen (``lsdtools desktop``);
- ``lsdtools-gui open FILE`` opens a project; ``lsdtools-gui handle-url URL`` follows an ``lsd://`` link;
- a single bare argument (as the XDG ``%u`` field passes it) is either, by its form.

It runs the same ``lsdtools`` commands, as a child of this interpreter with no console, and reads their
result document. A link never acts unasked: ``handle-url`` first says what the link asks, the person
answers a dialog, and only then does it run again with ``--yes``. A failure is shown in a dialog, with its
hint, since there is no terminal to read.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

__all__ = ["main"]

TITLE = "LSD"


def _command(raw: list[str]) -> tuple[list[str], list[str]]:
    """The global options the association was registered with, and the lsdtools command its arguments mean."""
    from .report import split_globals

    _options, rest = split_globals(raw)
    globals_ = raw[:len(raw) - len(rest)] if raw[len(raw) - len(rest):] == rest else []
    if not rest:
        return globals_, ["desktop"]
    if rest[0] in ("open", "handle-url", "desktop"):
        return globals_, rest
    if len(rest) == 1:
        return globals_, ["handle-url", rest[0]] if rest[0].lower().startswith("lsd:") else ["open", rest[0]]
    return globals_, rest


def _run(arguments: list[str], *, here: bool = False) -> dict:
    """One ``lsdtools --json`` command in a windowless child; its result document.

    The child starts in the interpreter's own folder: ``-m`` puts the working directory on ``sys.path``,
    and an association may start in a folder of downloaded files (a double-clicked project's), whose
    planted module must never be imported. Paths reach the child absolute (:func:`main`).

    ``here`` runs it in this process instead (``open``: it starts the Desktop itself, and a second interpreter
    would only delay the window)."""
    if here:
        return _run_here(arguments)
    flags = 0x08000000 if sys.platform.startswith("win") else 0  # CREATE_NO_WINDOW: no console flashes
    done = subprocess.run([sys.executable, "-m", "lsdtools._manager", "--json", *arguments],
                          cwd=os.path.dirname(os.path.abspath(sys.executable)),
                          stdin=subprocess.DEVNULL, capture_output=True, creationflags=flags)
    lines = done.stdout.decode("utf-8", "replace").strip().splitlines()
    try:
        document = json.loads(lines[-1]) if lines else None
    except ValueError:
        document = None
    if type(document) is not dict or "ok" not in document:
        tail = done.stderr.decode("utf-8", "replace").strip()[-600:]
        return {"ok": False, "error": {"message": f"lsdtools {' '.join(arguments)} failed (exit {done.returncode})",
                                       "hint": tail}}
    return document


def _run_here(arguments: list[str]) -> dict:
    """One ``lsdtools --json`` command in this process; its result document (stdout carries only that)."""
    import contextlib
    import io

    from .cli import main as lsdtools

    output, progress = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(progress):
        status = lsdtools(["--json", *arguments])
    lines = output.getvalue().strip().splitlines()
    try:
        document = json.loads(lines[-1]) if lines else None
    except ValueError:
        document = None
    if type(document) is not dict or "ok" not in document:
        return {"ok": False, "error": {"message": f"lsdtools {' '.join(arguments)} failed (exit {status})",
                                       "hint": progress.getvalue().strip()[-600:]}}
    return document


def _windows_box(text: str, flags: int) -> int:
    import ctypes

    return ctypes.windll.user32.MessageBoxW(None, text, TITLE, flags | 0x10000)  # MB_SETFOREGROUND


def _show(text: str) -> None:
    """An error the person sees; stderr where no dialog tool exists."""
    if sys.platform.startswith("win"):
        _windows_box(text, 0x10)  # MB_ICONERROR
        return
    if sys.platform == "darwin":
        script = ["-e", "on run argv", "-e", "display alert (item 1 of argv) message (item 2 of argv)",
                  "-e", "end run"]
        subprocess.run(["osascript", *script, TITLE, text], check=False, timeout=3600)
        return
    for tool, argv in (("zenity", ["zenity", "--error", "--title", TITLE, "--text", text]),
                       ("kdialog", ["kdialog", "--title", TITLE, "--error", text]),
                       ("notify-send", ["notify-send", TITLE, text])):
        if shutil.which(tool):
            subprocess.run(argv, check=False, timeout=3600)
            return
    print(f"{TITLE}: {text}", file=sys.stderr)


def _ask(question: str) -> bool:
    """Whether the person agrees; no where a dialog cannot be shown (a link never acts unasked)."""
    if sys.platform.startswith("win"):
        return _windows_box(question, 0x1 | 0x20) == 1  # MB_OKCANCEL | MB_ICONQUESTION -> IDOK
    if sys.platform == "darwin":
        script = ["-e", "on run argv", "-e",
                  'display dialog (item 2 of argv) with title (item 1 of argv) buttons {"Cancel", "OK"} '
                  'default button "OK"', "-e", "end run"]
        return subprocess.run(["osascript", *script, TITLE, question], check=False, capture_output=True,
                              timeout=3600).returncode == 0
    for tool, argv in (("zenity", ["zenity", "--question", "--title", TITLE, "--text", question]),
                       ("kdialog", ["kdialog", "--title", TITLE, "--yesno", question])):
        if shutil.which(tool):
            return subprocess.run(argv, check=False, timeout=3600).returncode == 0
    print(f"{TITLE}: {question} (no dialog tool to ask with: install zenity or kdialog)", file=sys.stderr)
    return False


def _failed(document: dict) -> int:
    error = document.get("error") or {}
    message = error.get("message") or "lsdtools failed"
    _show(message + (f"\n\n{error['hint']}" if error.get("hint") else ""))
    from .errors import EXIT_STATUS

    return EXIT_STATUS.get(error.get("code"), 1)


def main(argv: list[str] | None = None) -> int:
    globals_, command = _command(list(sys.argv[1:] if argv is None else argv))
    if command[0] in ("open", "handle-url") and len(command) != 2:
        # An association passes exactly one file or link; anything more (a --yes above all) is not one.
        _show(f"lsdtools-gui {command[0]} takes one {'project' if command[0] == 'open' else 'link'}")
        return 2
    if command[0] == "open":
        command = ["open", os.path.abspath(command[1])]
    if command[0] == "handle-url":
        # A link comes from any web page: it acts only once the person agrees to what it asks.
        plan = _run([*globals_, *command])
        if not plan.get("ok"):
            return _failed(plan)
        if not _ask(plan["data"]["question"]):
            return 0
        command = [*command, "--yes"]
    document = _run([*globals_, *command], here=command[0] == "open")
    required = (document.get("data") or {}).get("runtime_required") if not document.get("ok") else None
    if isinstance(required, str) and "--runtime" not in globals_:
        # A shared session runs in its host's exact runtime. The host chose it, so the person decides
        # whether to join with it (a signed catalog runtime, verified and installed when missing).
        if not _ask(f"This session's host runs LSD {required.split('/')[0]}. Join with that version "
                    "(it is installed first if this computer does not have it)?"):
            return 0
        document = _run([*globals_, "--runtime", required, *command])
    return 0 if document.get("ok") else _failed(document)
