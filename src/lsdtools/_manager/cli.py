"""The ``lsdtools`` command (lsdtools-cli-v1): its outer commands, and the dispatch of every other one.

Outer commands need no runtime: ``setup``, ``runtime ...``, ``doctor``, ``version`` and ``guide``; and
``verify``, the release check of one installed runtime, which lsdtools runs from outside it. ``open`` starts
the selected runtime's Desktop directly, with no runtime command in between. ``python`` runs python's own
command line in the selected runtime (``LSDCli.exe dev run``); any other command runs as
``<runtime>/LSDCli.exe lsdtools <argv>``, its argv unchanged.

With ``--json`` stdout carries exactly one ``lsdtools.result.v1`` document and progress goes to stderr as
``lsdtools.progress.v1`` NDJSON lines.
"""
from __future__ import annotations

import json
import os
import re
import sys

from . import VERSION
from .errors import ManagerError
from .report import Options, Reporter, split_globals

__all__ = ["main"]

_OUTER = ("setup", "runtime", "verify", "doctor", "version", "guide", "mcp-config", "handlers", "open")


def _context(options: Options, *, platform_required: bool = True):
    """The target, the home and this platform's runtime store. Without *platform_required*, a platform LSD
    has no runtime for yet gives no store (None) instead of exit 69: listing and diagnosing still work."""
    from .manifests import platform_row
    from .paths import platform_id, resolve_home, store_root
    from .store import Store
    from .targets import get_target

    target = get_target(options.target)
    home = resolve_home(options.home, target.name)
    system, arch = platform_id()
    try:
        platform = platform_row(system, arch)
    except ManagerError:
        if platform_required:
            raise
        return target, home, None
    store = Store(store_root(home, options.store), target, system=system, arch=arch, platform=platform)
    return target, home, store


def _catalog(options: Options, target):
    from .catalog import Catalog
    from .paths import platform_id
    from .transport import Transport

    if options.offline:
        raise ManagerError("unavailable", "this needs the server, and --offline was given")
    system, arch = platform_id()
    return Catalog(Transport(target), system=system, arch=arch, track=options.track)


def _install(options: Options, reporter: Reporter, selector: str | None, *, make_default: bool,
             repair: bool = False) -> dict:
    from .locks import store_lock

    target, home, store = _context(options)
    catalog = _catalog(options, target)
    row = catalog.select(selector or options.runtime or "latest")
    with store_lock(store.root, waiting=lambda: reporter.note(f"waiting for another lsdtools writing {store.root}")):
        store.require_store_file(create=True)
        installation, wrote = store.install(catalog, row, progress=reporter.progress, repair=repair)
        if make_default:
            store.set_default(installation)
            _follow_default(home, store)
    reporter.runtime = installation.coordinate
    return {"runtime": installation.to_json(), "installed": wrote, "default": make_default, "home": str(home),
            "store": str(store.root)}


def _cmd_setup(options, reporter, args) -> int:
    data = _install(options, reporter, args.runtime, make_default=True, repair=args.repair)
    verb = "Installed" if data["installed"] else "Verified"
    lines = [f"{verb} LSD {data['runtime']['version']} ({data['runtime']['selector'][:18]}...) "
             f"as the default runtime in {data['store']}"]
    if args.with_defaults:
        from .launch import run_result
        from .store import Verify

        _target, home, store = _context(options)
        reporter.note("installing the default packages")
        result = run_result(store.default(Verify.ROW), ["install", "--defaults"], home=home, cwd=os.getcwd())
        reporter.warnings.extend(result.get("warnings") or [])
        if not result.get("ok"):
            error = result.get("error") or {}
            raise ManagerError(error.get("code", "failed"), f"the default packages: {error.get('message', '')}",
                               hint=error.get("hint", ""), data=data)
        data["defaults"] = result["data"]
        lines.append(f"installed {len(result['data']['installed'])} default package(s)")
    if args.register_handlers:
        data["handlers"] = _register_handlers(options)
        lines.append(".lsd files and lsd:// links now open LSD")
    return reporter.finish(data, "\n".join(lines))


def _installed_script(name: str) -> str:
    """The console or GUI script *name* this Python installed lsdtools with: never one found on PATH or in
    the working folder, whose copy (planted, or merely older) would be written into a configuration."""
    import sysconfig

    executable = f"{name}.exe" if sys.platform.startswith("win") else name
    folders = [os.path.dirname(sys.executable), sysconfig.get_path("scripts"),
               sysconfig.get_path("scripts", sysconfig.get_preferred_scheme("user"))]
    found = next((os.path.join(folder, executable) for folder in folders
                  if folder and os.path.isfile(os.path.join(folder, executable))), None)
    if found is None:
        raise ManagerError("not_found", f"could not find the {name} command this Python installed",
                           hint="reinstall lsdtools (pip install --force-reinstall lsdtools)")
    return os.path.abspath(found)


def _global_arguments(options: Options) -> list[str]:
    """The global options a configuration that runs lsdtools later repeats (the default target is implied)."""
    arguments = []
    for name in ("home", "store", "target", "track", "runtime"):
        value = getattr(options, name)
        if value and not (name == "target" and value == "production"):
            arguments += [f"--{name}", str(value)]
    return arguments


#: Written into a home when its file associations are registered: the lsdtools-gui command line they run (or
#: would run), which a runtime's window starts for a project pinned to a runtime the home lacks
#: (lsd_platform.runtime_launch.LSDTOOLS_HANDLERS_FILE).
_HANDLERS_RECORD = "lsdtools-handlers-v1.json"


def _register_handlers(options: Options) -> dict:
    """Register this user's associations. A double-clicked project opens in the home's default runtime's
    Desktop directly when the home's store is its own (no lsdtools process before the window), else in
    lsdtools-gui; links always run lsdtools-gui, whose command line the home records."""
    from . import handlers
    from .canonical import canonical_bytes

    gui = [_installed_script("lsdtools-gui"), *_global_arguments(options)]
    _target, home, store = _context(options, platform_required=False)
    os.makedirs(home, exist_ok=True)
    record = home / _HANDLERS_RECORD
    temporary = record.with_name(f".{record.name}.{os.urandom(6).hex()}.tmp")
    temporary.write_bytes(canonical_bytes({"gui": gui, "schema_version": 1}))
    os.replace(temporary, record)
    return handlers.register(gui, desktop=_direct_desktop(home, store))


def _direct_desktop(home, store) -> str | None:
    """The Desktop a double-clicked project opens in directly: the default runtime's, in a home whose store is
    its own (that runtime then knows its home, lsd_packaging.home); None when lsdtools-gui opens it."""
    from .paths import WINDOWS
    from .store import Verify

    if not WINDOWS or store is None or os.path.normcase(str(store.root)) != os.path.normcase(str(home / "runtime")):
        return None
    default = store.default(Verify.ROW)
    return str(default.executable("desktop")) if default is not None else None


def _follow_default(home, store) -> None:
    """A double-click that opens this home's default runtime directly follows a change of that default (or
    its removal); an association lsdtools-gui opens, or another home's, is left as it is."""
    from pathlib import Path

    from . import handlers
    from .paths import WINDOWS

    if not WINDOWS:
        return
    current = handlers.direct_desktop()
    if current is None or not Path(current).is_relative_to(store.root):
        return
    try:
        with open(home / _HANDLERS_RECORD, encoding="utf-8") as handle:
            gui = json.load(handle)["gui"]
    except (OSError, ValueError, KeyError, TypeError):
        return  # no record of the gui command: the association is left for `lsdtools handlers register`
    handlers.register(gui, desktop=_direct_desktop(home, store), shortcut=False)


def _cmd_handlers(options, reporter, args) -> int:
    from . import handlers

    if args.handlers_action == "register":
        data = _register_handlers(options)
        return reporter.finish(data, ".lsd files and lsd:// links now open LSD for this user")
    if args.handlers_action == "unregister":
        data = handlers.unregister()
        return reporter.finish(data, "\n".join(f"removed {item}" for item in data["removed"])
                               or "no LSD file or link association was registered")
    data = handlers.status()
    return reporter.finish(data, "\n".join(f"{key}: {value or 'not registered'}" for key, value in data.items()))


def _cmd_runtime(options, reporter, args) -> int:
    from .locks import store_lock
    from .store import Verify

    action = args.runtime_action
    if action == "install":
        data = _install(options, reporter, args.selector, make_default=False, repair=args.repair)
        return reporter.finish(data, f"Installed LSD {data['runtime']['selector']}")
    target, home, store = _context(options, platform_required=False)
    if store is None:                       # LSD has no runtime for this platform yet: none is installed
        from .catalog import platform_row
        from .paths import platform_id

        try:
            platform_row(*platform_id())
        except ManagerError as unavailable:
            reporter.warn(unavailable.code, unavailable.message)
        if action == "list":
            return reporter.finish({"runtimes": [], "store": None}, "no runtime: LSD has none for this platform yet")
        if action == "verify":
            return reporter.finish({"verified": [], "full": args.full}, "no runtime is installed")
        if action == "gc":
            return reporter.finish({"freed_bytes": 0}, "freed 0.0 MB")
        raise ManagerError("not_found", "no runtime is installed: LSD has none for this platform yet")
    store.require_store_file(create=False)
    if action == "list":
        default = store.default(Verify.ROW)
        rows = [{**item.to_json(), "default": default is not None and item.coordinate == default.coordinate}
                for item in store.installations(Verify.ROW)]
        text = "\n".join(f"{'*' if row['default'] else ' '} {row['version']}  {row['artifact_sha256'][:12]}  "
                         f"{row['root']}" for row in rows) or "no runtime is installed (lsdtools setup)"
        return reporter.finish({"runtimes": rows, "store": str(store.root)}, text)
    selector = getattr(args, "selector", None) or options.runtime
    if action == "path":
        installation = store.find(selector, Verify.ROW)
        return reporter.finish({"path": str(installation.root)}, str(installation.root))
    if action == "verify":
        depth = Verify.FULL if args.full else Verify.SIGNED
        chosen = [store.find(selector, depth)] if selector else store.installations(depth)
        return reporter.finish({"verified": [item.to_json() for item in chosen], "full": args.full},
                               "\n".join(f"verified {item.selector}{' (every file)' if args.full else ''}"
                                         for item in chosen) or "no runtime is installed")
    with store_lock(store.root, waiting=lambda: reporter.note("waiting for another lsdtools")):
        if action == "default":
            installation = store.find(selector, Verify.SIGNED)
            store.set_default(installation)
            _follow_default(home, store)
            return reporter.finish({"runtime": installation.to_json()}, f"default runtime: {installation.selector}")
        if action == "remove":
            installation = store.find(selector, Verify.ROW)
            if not store.remove(installation):
                reporter.warn("incomplete", "a process that started meanwhile holds some of its files; "
                                            "lsdtools runtime gc deletes them once it ends")
            _follow_default(home, store)
            return reporter.finish({"removed": installation.to_json()}, f"removed {installation.selector}")
        if action == "gc":
            freed = store.gc()
            return reporter.finish({"freed_bytes": freed}, f"freed {freed / 1e6:.1f} MB")
    raise ManagerError("usage", f"unknown runtime action {action!r}")


def _cmd_doctor(options, reporter, args) -> int:
    from .store import Verify

    checks: list[dict] = []

    def check(name: str, run) -> None:
        try:
            detail = run()
            checks.append({"check": name, "ok": True, "detail": detail})
        except ManagerError as exc:
            checks.append({"check": name, "ok": False, "detail": exc.message, "code": exc.code, "hint": exc.hint})

    def python_check():
        import platform

        if sys.version_info < (3, 10):
            raise ManagerError("unavailable", "lsdtools needs Python 3.10 or newer")
        return f"{platform.python_implementation()} {platform.python_version()} ({sys.executable})"

    check("python", python_check)
    target, home, store = _context(options, platform_required=False)

    def platform_check():
        from .catalog import platform_row
        from .paths import platform_id

        row = platform_row(*platform_id())
        return row["id"]

    check("platform", platform_check)

    def server_check():
        catalog = _catalog(options, target)
        trust = catalog.trust()
        detail = f"{target.origin}: keys {', '.join(trust.updates)} (updates), {', '.join(trust.catalog)} " \
                 f"(catalog) trusted"
        if store is None:                   # no runtime is published for this platform: the keys only
            return detail
        return f"{detail}; {catalog.track} head {catalog.head().coordinate['version']}"

    if not options.offline:
        check("server", server_check)

    def store_check():
        store.require_store_file(create=False)
        installed = store.installations(Verify.SIGNED)
        default = store.default(Verify.ROW)
        return (f"{store.root}: {len(installed)} runtime(s) verified"
                + (f", default {default.selector}" if default else ", none installed (lsdtools setup)"))

    if store is not None:                   # this platform's store, once it has runtimes
        check("store", store_check)
    ok = all(item["ok"] for item in checks)
    text = "\n".join(f"{'ok ' if item['ok'] else 'BAD'} {item['check']}: {item['detail']}"
                     + (f"\n    hint: {item['hint']}" if not item["ok"] and item.get("hint") else "")
                     for item in checks)
    if ok:
        return reporter.finish({"checks": checks, "home": str(home)}, text)
    failed = next(item for item in checks if not item["ok"])
    if not options.json:
        print(text, flush=True)  # before the error line, which goes to stderr
    report = {"checks": checks, "home": str(home)}
    return reporter.finish(report, "", ManagerError(failed.get("code", "failed"),
                                                    f"doctor: {failed['check']} failed: {failed['detail']}",
                                                    hint=failed.get("hint", ""), data=report))


def _cmd_version(options, reporter, args) -> int:
    import platform

    data = {"lsdtools": VERSION, "python": platform.python_version()}
    try:
        from .store import Verify

        _target, _home, store = _context(options)
        default = store.default(Verify.ROW) if os.path.isdir(store.root) else None
        data["default_runtime"] = default.to_json() if default else None
    except ManagerError as exc:
        data["default_runtime"] = None
        reporter.warn(exc.code, exc.message)
    runtime = data["default_runtime"]
    return reporter.finish(data, f"lsdtools {VERSION}" + (f" (default runtime {runtime['selector']})" if runtime else ""))


_GUIDE = {
    "quickstart": """lsdtools: LSD for agents and people, on this computer.

  lsdtools setup                            install the current signed LSD runtime (once)
  lsdtools new project work/game            a new project, pinned to that runtime (work/game/project.lsd)
  lsdtools open work/game/project.lsd       open it in a Desktop window (--window hidden: off the screen)
  lsdtools snapshot latest --out game.png   a picture the app renders (never the screen)
  lsdtools action latest describe           the window's action catalog; then action SESSION KIND -p k=v
  lsdtools close latest                     close the window (its edits are already saved)
  lsdtools run work/game/project.lsd        run the project's pipelines headless
  lsdtools python script.py a b             run a script inside the runtime (python's own command line)
  lsdtools install owner/name               a package from the signed catalog (-e ./folder links one)
  lsdtools mcp                              an MCP server for an agent (lsdtools guide mcp)
  lsdtools --json <command>                 one lsdtools.result.v1 document on stdout

Topics: agents, mcp, projects, packages, json, troubleshooting. Every command exits with lsdtools-cli-v1's
status (0 ok, 2 usage, 66 not found, 69 unavailable here, 73 in use, 75 retry, 77 a person must act, 78 a
trust check failed); lsdtools commands lists what the installed runtime implements.""",
    "agents": """Driving LSD as an agent.

- Use --json: stdout is then exactly one lsdtools.result.v1 document {ok, data, warnings, error{code,
  message, hint, retryable}}. Decide from error.code and the exit status, never from the text.
- Open windows hidden (open --window hidden): they draw, and their snapshots work, but nothing reaches
  the person's screen, taskbar or keyboard focus.
- Observe, act, verify. Read the window (lsdtools action SESSION describe_views, describe_project_tree),
  act with one stable action, then read again or take lsdtools snapshot SESSION --out shot.png.
- Readiness is a signal: open returns once the window announced its door; nothing needs a sleep.
- Exit 77 (needs_human) means a person decides: a paid package, an unreviewed URL, an approval, a
  sign-in. Report it; never work around it. Opening or creating a project never enables its project
  code: change behaviour through packages (lsdtools install -e ./my-package, then lsdtools reload).
- A project names its exact runtime; lsdtools runs it in that one (installing it when missing).""",
    "mcp": """lsdtools mcp: an MCP server on stdio that opens, drives and closes this home's LSD windows.

  lsdtools mcp-config --client claude       the server entry for Claude Code (also: codex, generic)
  lsdtools mcp --project work/game/project.lsd   open a project at start and attach to its window
  lsdtools mcp --window                     show the windows it opens (by default they are hidden)

Its lsd_* tools (lsd_status, lsd_open_project, lsd_new_project, lsd_attach, lsd_close, lsd_reload,
lsd_install, lsd_packages, lsd_templates, lsd_run) each run one lsdtools command and return its result
document. While attached, the window's own actions are ui_* tools (tools/list_changed announces them);
lsd_action sends them by kind. Windows it opened close with it unless opened with keep_open.""",
    "projects": """Projects: one .lsd file and its folder, pinned to the exact runtime that opens it.

  lsdtools templates                        what new projects can start from
  lsdtools new project DIR [--template ID]  a new project (DIR/project.lsd), pinned to this runtime
  lsdtools project check P.lsd              its runtime pin and whether its packages are installed
  lsdtools project prepare P.lsd            install what its saved package graphs need
  lsdtools --runtime X project pin P.lsd --replace   move it to another installed runtime
  lsdtools open P.lsd / close / reload      a window on it (reload loads changed package code)
  lsdtools host P.lsd                       its headless Project Host, without a window
  lsdtools run P.lsd [--entity NAME]        run its pipelines headless (refused, 73, while a window has it)

An unpinned project is pinned to the runtime that first opens it, and the warning says so. Opening or
creating a project is data-only: its project code runs only after a person reviews and enables it.""",
    "packages": """Packages: what a project's pipelines, views and worlds are made of.

  lsdtools list                             installed packages
  lsdtools info owner/name                  its catalog versions, and which one is installed
  lsdtools install owner/name[@x.y.z]       from the signed catalog (77 when a person must decide: paid)
  lsdtools install ./folder                 a copy of a package folder
  lsdtools install -e ./folder              linked by reference: edit it, then lsdtools reload SESSION
  lsdtools update [owner/name]              installed catalog packages to their current versions
  lsdtools uninstall owner/name

A linked package is an author's own: its manifest's publisher is blank (a published manifest names its
publisher and declares catalog delivery). An https:// URL installs only with --unreviewed, after a person
has read its source.""",
    "json": """The machine-readable contract (lsdtools-cli-v1).

With --json, stdout carries exactly one document, also on failure:
  {"schema": "lsdtools.result.v1", "command", "ok", "data", "warnings": [{code, message}],
   "error": null | {code, message, hint, retryable}, "lsdtools", "runtime", "elapsed_ms"}
data is the command's own; on a failure it is null unless the failure has a result of its own (run's
report). Progress goes to stderr as NDJSON lsdtools.progress.v1 lines. python, test and mcp are the
exceptions: their stdout is the program's (mcp: the MCP protocol).

Exit status: 0 ok, 1 failed, 2 usage, 65 invalid data, 66 not found, 69 unavailable here, 70 internal,
73 exists or in use, 75 temporary (retry), 76 protocol, 77 a person must act, 78 trust.""",
    "troubleshooting": """When something does not work.

  lsdtools doctor                           Python, the server's keys, the store and this platform
  lsdtools sessions                         the windows (with their doors) and Project Hosts running
  lsdtools logs [SESSION]                   a window's log and its error log
  lsdtools runtime verify --full            hash every file of the runtime against its signature
  lsdtools runtime install X --repair       reinstall damaged files from fresh signed archives
  lsdtools verify                           the release check of the runtime, end to end

- 78 trust: a signature, key or digest did not verify; never bypass it, repair or reinstall.
- 75 temporary: retry (network, a lock another lsdtools holds, a window still closing).
- 73 in use: close the window holding it (lsdtools close SESSION); a runtime that runs cannot be removed.
- A first full verify or launch is slow on Windows: its malware scan reads every new file once.""",
}


def _cmd_mcp_config(options, reporter, args) -> int:
    """The MCP server entry a client needs to start ``lsdtools mcp`` with these global options."""
    command = _installed_script("lsdtools")
    arguments = [*_global_arguments(options), "mcp"]
    entry = {"command": command, "args": arguments}
    if args.client == "codex":
        quoted = ", ".join(json.dumps(item) for item in arguments)
        text = f"[mcp_servers.lsd]\ncommand = {json.dumps(command)}\nargs = [{quoted}]"
        config = {"mcp_servers": {"lsd": entry}}
    elif args.client == "claude":
        config = {"mcpServers": {"lsd": entry}}
        text = json.dumps(config, indent=2)
    else:
        config = entry
        text = json.dumps(config, indent=2)
    return reporter.finish({"client": args.client, "config": config}, text)


def _cmd_verify(options, reporter, args) -> int:
    from .store import Verify
    from .verify import verify_runtime

    target, home, store = _context(options)
    store.require_store_file(create=False)
    installation = store.find(args.selector or options.runtime or "default", Verify.SIGNED)
    data = verify_runtime(store, installation, project=args.project, reporter=reporter)
    return reporter.finish(data, f"verified {installation.selector} end to end ({data['integrity_model']}); "
                                 f"evidence in {data['verifier_home']}")


def _cmd_guide(options, reporter, args) -> int:
    topic = args.topic or "quickstart"
    if topic not in _GUIDE:
        raise ManagerError("not_found", f"no guide topic {topic!r}", hint=f"topics: {', '.join(_GUIDE)}")
    return reporter.finish({"topic": topic, "text": _GUIDE[topic]}, _GUIDE[topic])


def _open_arguments(rest: list[str]):
    """``open``'s arguments, read without argparse, whose import and parser cost a launch about 60 ms
    (Python 3.14: help colours and the terminal width). None for anything else, which argparse then reads,
    and reports (``_parser``, the grammar's authority)."""
    from types import SimpleNamespace

    values = {"command": "open", "project": None, "no_door": False, "window": "normal", "wait": "ready",
              "timeout": 180.0}
    choices = {"--window": ("normal", "hidden"), "--wait": ("ready", "launched")}
    items = iter(rest[1:])
    for item in items:
        name, equals, inline = item.partition("=") if item.startswith("--") else (item, "", "")
        if item == "--no-door":
            values["no_door"] = True
        elif name in ("--window", "--wait", "--timeout"):
            value = inline if equals else next(items, None)
            if value is None:
                return None
            if name == "--timeout":
                try:
                    values["timeout"] = float(value)
                except ValueError:
                    return None
            elif value in choices[name]:
                values[name[2:]] = value
            else:
                return None
        elif item.startswith("-") or values["project"] is not None:
            return None
        else:
            values["project"] = item
    return SimpleNamespace(**values) if values["project"] is not None else None


def _parser(command: str | None = None) -> argparse.ArgumentParser:
    """The outer commands' parser; with ``command``, only that command's (about 50 ms less to build than all,
    on every ``open``)."""
    import argparse

    parser = argparse.ArgumentParser(prog="lsdtools", description="Install and run exact signed LSD runtimes.")
    commands = parser.add_subparsers(dest="command", required=True)

    def wanted(name: str) -> bool:
        return command is None or command == name

    repair_help = "re-read every file and reinstall what is damaged from fresh archives"
    if wanted("setup"):
        setup = commands.add_parser("setup", help="install the track's current runtime and make it the default")
        setup.add_argument("--runtime", help="latest, x.y.z or x.y.z/<sha256 prefix>")
        setup.add_argument("--repair", action="store_true", help=repair_help)
        setup.add_argument("--with-defaults", action="store_true",
                           help="also install the Core packages a person's LSD starts with")
        setup.add_argument("--register-handlers", action="store_true",
                           help="also make .lsd files and lsd:// links open LSD for this user")
    if wanted("runtime"):
        runtime = commands.add_parser("runtime", help="the installed runtimes")
        actions = runtime.add_subparsers(dest="runtime_action", required=True)
        actions.add_parser("list")
        actions.add_parser("gc")
        for name in ("install", "default", "remove"):
            sub = actions.add_parser(name)
            sub.add_argument("selector")
            if name == "install":
                sub.add_argument("--repair", action="store_true", help=repair_help)
        for name in ("path", "verify"):
            sub = actions.add_parser(name)
            sub.add_argument("selector", nargs="?")
            if name == "verify":
                sub.add_argument("--full", action="store_true", help="hash every file of the runtime")
    if wanted("verify"):
        verify = commands.add_parser("verify", help="the release check of one installed runtime, end to end")
        verify.add_argument("selector", nargs="?", help="the runtime (default: the home's default)")
        verify.add_argument("--project", help="a self-contained .lsd fixture (default: a blank project)")
    if wanted("doctor"):
        commands.add_parser("doctor", help="check Python, the server, the store and the platform")
    if wanted("version"):
        commands.add_parser("version")
    if wanted("guide"):
        guide = commands.add_parser("guide", help="the built-in guide")
        guide.add_argument("topic", nargs="?")
    if wanted("mcp-config"):
        mcp_config = commands.add_parser("mcp-config", help="the MCP server entry for a client")
        mcp_config.add_argument("--client", choices=("claude", "codex", "generic"), default="generic")
    if wanted("handlers"):
        handlers = commands.add_parser("handlers", help="this user's .lsd file and lsd:// link associations")
        handlers.add_argument("handlers_action", choices=("register", "unregister", "status"))
    if wanted("open"):
        open_ = commands.add_parser("open", help="open a project in its runtime's Desktop")
        open_.add_argument("project", help="a .lsd project")
        open_.add_argument("--no-door", action="store_true", help="no private action door for agents")
        open_.add_argument("--window", choices=("normal", "hidden"), default="normal",
                           help="hidden: the window draws and its snapshots work, but it never reaches the screen")
        open_.add_argument("--wait", choices=("ready", "launched"), default="ready")
        open_.add_argument("--timeout", type=float, default=180.0, help="seconds to wait for the workspace")
    return parser

#: The window's ready line in its log, when it has no door (``lsd_project_sync.native_composition``), and its
#: error line (``lsd_project_sync.native_client``): before ready, an error ends the wait.
_READY = b"[native] workspace ready"
_ERROR = b"[native] error "


def _cmd_open(options, reporter, args) -> int:
    """Start the Desktop of the runtime the project is pinned to (else the default) on it, directly.

    A pinned project's Project Host starts at the same moment, beside the window, which adopts it. The window
    does the rest itself: it pins an unpinned project to its runtime and starts its host, and has its runtime
    install what a host finds missing. With a door it announces its action endpoint in
    ``<home>/native-sessions/`` once its workspace is ready; that announcement is the signal waited for."""
    import base64
    import time
    from pathlib import Path

    from .launch import start_detached

    if ":" in args.project and not args.project.lower().endswith(".lsd"):
        raise ManagerError("unavailable", "opening a package's example (owner/name:entry) arrives with the "
                           "package repositories (P3)", hint="lsdtools templates, then lsdtools new project")
    project = Path(args.project).resolve()
    if project.suffix.casefold() != ".lsd" or not project.is_file():
        raise ManagerError("usage", f"{args.project} is not a .lsd project")
    if args.window == "hidden" and args.no_door:
        raise ManagerError("usage", "a hidden window needs its door: nothing else can drive or close it")
    home, installation, pinned = _runtime_for(options, ["open", str(project)])
    token = "" if args.no_door else base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    extra = {"LSD_MCP_DESKTOP_TOKEN": token, "LSD_MCP_DESKTOP_PORT": "0"} if token else {}
    if args.window == "hidden":
        extra["LSD_NATIVE_WINDOW"] = "hidden"  # the environment: the launcher takes no option after a project
    if pinned is not None:
        # A pinned project's Project Host starts beside its window instead of after it; the window waits for that
        # host, and starts its own only if this one ends first (lsd_desktop.app). The digest is the host's proof
        # that the document it opens is the one read here (lsd_platform.application_identity).
        import hashlib

        digest = hashlib.sha256(project.read_bytes()).hexdigest()
        host = start_detached(installation, "desktop", ["--mode", "project-host", str(project), "--stop-when-idle"],
                              home=home, extra={"LSD_LAUNCH_PROJECT_SHA256_V1": digest})
        extra["LSD_NATIVE_HOST_PROCESS"] = str(host.pid)
    process = start_detached(installation, "desktop", [str(project)], home=home, extra=extra or None)
    log = home / "logs" / f"desktop-{process.pid}.log"
    unpinned = pinned is None and not options.runtime  # the project was read and names no runtime
    data = {"window_pid": process.pid, "project": str(project), "pinned": installation.coordinate if unpinned else None,
            "log": str(log), "session": None, "door": None, "window": args.window}
    if unpinned:
        reporter.warn("pinned_default", f"{project.name} named no runtime; the window pins it to "
                                        f"{installation.selector}")
    if args.wait == "ready":
        deadline = time.monotonic() + args.timeout
        while True:
            if token:
                record = _door_record(home, token)
                if record is not None:
                    data["session"], data["door"] = record["pid"], {"endpoint": record["endpoint"]}
                    break
            tail = _tail(log)
            if not token and _READY in tail:
                data["session"] = process.pid
                break
            if _ERROR in tail:
                line = tail[tail.rindex(_ERROR) + len(_ERROR):].split(b"\n", 1)[0].decode("utf-8", "replace").strip()
                if args.window == "hidden":
                    process.terminate()  # nobody can see or close a hidden window that has no door yet
                raise ManagerError("failed", f"the Desktop (pid {process.pid}) could not open {project.name}: {line}",
                                   hint=f"lsdtools logs {process.pid}" if args.window == "hidden"
                                   else "its window shows the reason; close it there")
            if process.poll() is not None:
                raise ManagerError("failed", f"the Desktop (pid {process.pid}) exited before its workspace was "
                                   f"ready:\n{_tail(log).decode('utf-8', 'replace')[-1500:]}",
                                   hint=f"lsdtools logs {process.pid}")
            if time.monotonic() > deadline:
                raise ManagerError("temporary", f"the Desktop (pid {process.pid}) was not ready within "
                                   f"{args.timeout:.0f} s", hint=f"its log: {log}")
            time.sleep(0.05)  # reading the files the window writes; its announcement is the signal
    session = data["session"] if data["session"] is not None else process.pid
    return reporter.finish(data, f"opened {project.name} (session {session})")


def _tail(log) -> bytes:
    try:
        with open(log, "rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - 65536))
            return handle.read()
    except OSError:
        return b""  # the window has not written its log yet


def _door_record(home, token: str) -> dict | None:
    """The window's door announcement carrying ``token`` (``lsd_collab.native_discovery``), if it is there."""
    import hmac

    from .canonical import strict_loads

    directory = home / "native-sessions"
    try:
        names = os.listdir(directory)
    except OSError:
        return None
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(directory / name, "rb") as handle:
                record = strict_loads(handle.read(65537), maximum=65536, label=name)
        except (OSError, ManagerError):
            continue  # being written, or not a record: read it again next time
        if (type(record) is dict and type(record.get("token")) is str and hmac.compare_digest(record["token"], token)
                and type(record.get("pid")) is int and type(record.get("endpoint")) is str):
            return record
    return None


def _project_pin(argv: list[str]) -> str | None:
    """The runtime selector a project named on the command line is pinned to (its ``desktop_runtime``), if any.

    Only the pin is read, with the standard library; a project that cannot be read is left to the runtime
    command, which reports it properly."""
    from .canonical import strict_loads

    for argument in argv[1:]:
        if not argument.lower().endswith(".lsd") or not os.path.isfile(argument):
            continue
        try:
            with open(argument, "rb") as handle:
                document = strict_loads(handle.read(64 * 1024 * 1024 + 1), maximum=64 * 1024 * 1024, label=argument)
        except (OSError, ManagerError):
            return None
        pin = document.get("desktop_runtime") if type(document) is dict else None
        coordinate = pin.get("coordinate") if type(pin) is dict else None
        if type(coordinate) is dict and type(coordinate.get("version")) is str \
                and type(coordinate.get("artifact_sha256")) is str:
            return f"{coordinate['version']}/{coordinate['artifact_sha256']}"
        return None
    return None


def _runtime_for(options: Options, argv: list[str]):
    """``(home, installation, pinned)``: the runtime a command runs in, and the pin it was chosen by, if any.

    The runtime is ``--runtime``, else the exact one a project on the command line is pinned to
    (installed when it is missing), else the home's default (set up from the track's head when none is
    installed). lsdtools-cli-v1 "Runtime selection". It was verified when installed; a launch reads its
    ledger row and finds its files (``Verify.ROW``), it does not hash them again."""
    from .store import Verify

    target, home, store = _context(options)
    store.require_store_file(create=False)
    pinned = None if options.runtime else _project_pin(argv)
    selector = options.runtime or pinned or "default"
    try:
        installation = store.find(selector, Verify.ROW)  # verified at install: trusted at launch
    except ManagerError as exc:
        if exc.code != "not_found" or options.no_auto_setup or options.offline:
            raise
        reporter = Reporter(options, "setup")
        if selector == "default":
            reporter.note("no runtime is installed: setting up the track's current one first")
            _install(options, reporter, None, make_default=True)
        else:
            reporter.note(f"installing runtime {selector[:18]} for {'the project' if pinned else 'this command'}")
            _install(options, reporter, selector, make_default=False)
        installation = store.find(selector, Verify.ROW)
    return home, installation, pinned


def _dispatch(options: Options, argv: list[str]) -> int:
    """``python`` and every runtime command, in the selected runtime (:func:`_runtime_for`)."""
    home, installation, _pinned = _runtime_for(options, argv)
    from .launch import run_attached

    if argv[0] == "python":
        arguments = ["dev", "run", *argv[1:]]
    else:
        arguments = ["lsdtools", *(["--json"] if options.json else []), *argv]
    return run_attached(installation, "cli", arguments, home=home, cwd=os.getcwd())


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        options, rest = split_globals(argv)
    except ManagerError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return exc.status
    if not rest or rest[0] in ("-h", "--help"):
        _parser().print_help()
        return 0 if rest else 2
    if rest[0] in ("--version",):
        print(f"lsdtools {VERSION}")
        return 0
    if rest[0] not in _OUTER:
        if not re.fullmatch(r"[a-z][a-z0-9-]*", rest[0]):
            return Reporter(options, rest[0]).finish(None, "", ManagerError(
                "usage", f"{rest[0]!r} is not an lsdtools command", hint="lsdtools --help"))
        try:
            return _dispatch(options, rest)
        except ManagerError as exc:
            return Reporter(options, rest[0]).finish(None, "", exc)
    args = (_open_arguments(rest) if rest[0] == "open" else None) or _parser(rest[0]).parse_args(rest)
    reporter = Reporter(options, args.command)
    handler = {"setup": _cmd_setup, "runtime": _cmd_runtime, "verify": _cmd_verify, "doctor": _cmd_doctor,
               "version": _cmd_version, "guide": _cmd_guide, "mcp-config": _cmd_mcp_config,
               "handlers": _cmd_handlers, "open": _cmd_open}[args.command]
    try:
        return handler(options, reporter, args)
    except ManagerError as exc:
        return reporter.finish(None, "", exc)
    except KeyboardInterrupt:
        return reporter.finish(None, "", ManagerError("temporary", "interrupted"))
    except OSError as exc:
        return reporter.finish(None, "", ManagerError("unavailable", f"{type(exc).__name__}: {exc}"))
