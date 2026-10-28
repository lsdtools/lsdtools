# lsdtools-cli-v1: the `lsdtools` command line

`pip install lsdtools` (or `uv tool install lsdtools`) gives one command, `lsdtools`. It installs
exact signed LSD runtimes and runs everything else inside one of them, the way Blender runs a script
with `blender --python`. An agent needs nothing else: no source checkout, no MSYS2, no Hub.

```
pip install lsdtools
lsdtools install https://github.com/lsdtools/terrain-stream
lsdtools open lsdtools/terrain-stream:fly --window hidden --json
lsdtools snapshot latest --out fly.png --json
lsdtools mcp                                   # or let an MCP client drive the window
```

This is the contract. Every row names the phase that lands it (P1 the manager, P2 the runtime
commands, P3 the agent features, P5 package repositories, P6 the Hub's retirement). It changes in
place at v1 until there are clients. `lsdtools commands --json` lists what the selected runtime
actually implements.

## Two halves, one command line

- **The outer half** is the wheel's stdlib-only manager, running in the user's Python 3.10 or newer.
  It sets up and verifies runtimes and starts them. It never imports the engine and never runs pip.
  The wheel's second entry point, `lsdtools-gui`, is what a person's double-click, link or Start
  menu runs: the same commands with no console (no argument: `desktop`; a `.lsd`: `open`; an
  `lsd://` link: `handle-url`, asking the person before `--yes`), a failure shown in a dialog.
- **Every other command** runs as `<runtime>/LSDCli.exe lsdtools <argv>` in the selected runtime, with
  the argv unchanged. A newer wheel never needs a newer runtime to pass a command through, and each
  command ships and is tested with the product that implements it.

## Conventions

- **Output.** Without `--json`, text for a person. With `--json`, stdout carries exactly one
  `lsdtools.result.v1` document (below): whatever engine or package code prints while the command
  runs goes to stderr. Progress goes to stderr: NDJSON `lsdtools.progress.v1` lines under `--json`,
  text otherwise. The exceptions are `python` and `test`, whose output and exit status are the
  program's own, and `mcp`, whose stdout is the MCP protocol.
- **No prompts.** A command never waits for input and never opens a browser, except `login`. A step
  only a person may take (project-code consent, sign-in, an unreviewed source) exits 77 with a hint.
- **No secrets in argv.** A token or invite arrives on stdin, in a file whose path is given, or from
  the environment variable the command names (`LSD_COLLAB_INVITE`, ...). Nothing a command prints
  contains one.
- **Project code is never enabled.** Opening or creating a `.lsd` is data-only. An agent changes
  behaviour through packages (`install -e`), never by granting project code (golden rule 7).
- **Readiness is a signal.** `open --wait ready` returns when the window has announced its door (with
  `--no-door`, when its log has the `[native] workspace ready` line); `host` returns when the Project
  Host's session record is reachable. Nothing waits by sleeping.

### Global options

They come before the command, or among its own options. For `python` and `test`, everything after
the command name belongs to the program, so global options go before it.

| option | environment | meaning |
|---|---|---|
| `--json` | `LSDTOOLS_JSON=1` | one result document on stdout |
| `--home DIR` | `LSD_HOME` | the LSD home (default: the target's, runtime-store-v1 `homes`) |
| `--store DIR` | `LSDTOOLS_STORE` | the runtime store, when not `<home>/runtime` (Grounds share one store across fresh homes) |
| `--target production\|development` | `LSDTOOLS_TARGET` | the server whose signed runtimes and catalog are used (default production) |
| `--track NAME` | `LSDTOOLS_TRACK` | the release track (default: the target's consumption track) |
| `--runtime SELECTOR` | `LSDTOOLS_RUNTIME` | the runtime to use (runtime selection, below) |
| `--offline` | `LSDTOOLS_OFFLINE=1` | use only what is installed; never contact a server |
| `--no-auto-setup` | `LSDTOOLS_NO_AUTO_SETUP=1` | exit 69 instead of installing a missing runtime |

A runtime `SELECTOR` is `latest`, a version `x.y.z` (its newest available build), or an exact
`x.y.z/<artifact sha256>` (a unique prefix of at least 12 hex digits is accepted).

An installed runtime's bytes come first from the target's artifact mirror (production: GitHub Releases,
`lsdtools/runtimes`), then from the server. Either source is held to the server's signed manifest (its
exact size and sha256), so a missing or wrong mirror file only falls back to the server.

### Exit status

| status | error codes | meaning |
|---|---|---|
| 0 | | done |
| 1 | `failed` | the operation failed for a reason in its own domain (a pipeline error, a refused action) |
| 2 | `usage` | the command line is wrong |
| 65 | `invalid_data` | an input document or archive is malformed |
| 66 | `not_found` | a file, package, project, session or runtime does not exist |
| 69 | `unavailable`, `platform_unavailable`, `component_missing` | not available here: this platform, a component, an offline resource |
| 70 | `internal` | a defect; the message says where |
| 73 | `exists`, `in_use` | the target exists, or a runtime or session is in use |
| 75 | `temporary` | retry later: network, server busy, lock held |
| 76 | `protocol` | a server, runtime or door answered outside its contract |
| 77 | `needs_human` | a person must act: consent, sign-in, `--unreviewed` |
| 78 | `trust` | a signature, key, digest or store target did not verify |

`python`, `test` and `play` exit with their program's own status. `run` exits 1 (`failed`) when an
entity fails, its document's `data` still the run's report.

### The result document

```json
{
  "schema": "lsdtools.result.v1",
  "command": "open",
  "ok": true,
  "data": {"session": "s-2f9c...", "project": "C:/work/fly/fly.lsd", "pinned": null},
  "warnings": [{"code": "pinned_default", "message": "fly.lsd had no runtime; pinned 1.0.0"}],
  "error": null,
  "lsdtools": "1.0.0rc1",
  "runtime": {"version": "1.0.0", "release_id": "f8e7...", "artifact_sha256": "b402...",
              "platform": "windows", "arch": "x86_64"},
  "elapsed_ms": 2140
}
```

`error` is `null` when `ok`, else `{code, message, hint, retryable}`. `runtime` is `null` for an
outer command that used none. `data` is the command's own (each row below names its keys); on a
failure it is `null`, unless the failure has a result of its own (`run`'s report).

## Outer commands (P1; no runtime needed)

| command | does | `data` |
|---|---|---|
| `setup [--runtime SELECTOR] [--component NAME]... [--with-defaults] [--register-handlers]` | install the signed Base and Desktop the track's head names (or the selector's), verify them and make them the default; idempotent. `--component`: `software-vulkan`, `devtools`, `toolchain` (P3). `--with-defaults`: then the default Core packages (`install --defaults` in the new default runtime); `--register-handlers`: then `handlers register` | `runtime`, `installed`, `default`, `home`, `store`, `defaults` (`install --defaults`' own `data`), `handlers` |
| `runtime list` | installed runtimes, newest first | `runtimes[]` |
| `runtime install SELECTOR` | install one more, without changing the default | `runtime` |
| `runtime default SELECTOR` | set the default | `runtime` |
| `runtime remove SELECTOR` | remove one; exit 73 while it runs | `removed` |
| `runtime gc` | remove debris, unreferenced Bases and downloads | `freed_bytes` |
| `runtime verify [SELECTOR] [--full]` | re-verify signatures and executables; `--full` hashes the whole tree | `verified[]` |
| `runtime path [SELECTOR]` | the installation's directory | `path` |
| `verify [SELECTOR] [--project FIXTURE]` (P2) | the exact-runtime release check, end to end, in place of the Hub's `verify_runtime`: every member of the runtime held deny-write with its names watched, the tree hashed, then in a fresh verifier home and one job no process leaves, the fixture (default: a blank project the runtime creates) pinned with `project pin --replace`, the Project Host and the Desktop started as lsdtools' own children, and the runtime's release verifier (`verifier/bootstrap.py`, envelope `LSD_VERIFIER_*`) adding, saving and rendering through the window's door; ok only when it exits 0, every process exited, nothing changed and the final hash matches. Windows (P7: Linux). Integrity model `quiescent-user-store-v1`: evidence on a quiet machine, never a sandbox | `ok`, `integrity_model`, `runtime`, `verifier_home`, `report`, `process_id`, `desktop_process_id`, `host_process_id`, `exit_code`, `members_held` |
| `doctor` | Python, TLS, clock, the target's keys against `/updates/v1/signing-key` and `/catalog/v1/signing-key`, the store, the platform; with a runtime, also its Vulkan, GTK and packages | `checks[]` |
| `version` | lsdtools, its API version and the default runtime | `lsdtools`, `api_version` |
| `guide [TOPIC]` | the built-in guide: `quickstart`, `agents`, `mcp`, `projects`, `packages`, `json`, `troubleshooting` (P2, P3); `exports` arrives with `export` (P3) | `topic`, `text` |
| `mcp-config [--client claude\|codex\|generic]` (P2) | the MCP server entry that starts this `lsdtools mcp` with these global options (`--home`, `--target`, ...), in that client's shape | `client`, `config` |
| `self update` / `self verify` | print the uv, pipx or pip command that updates the wheel, and check the installed wheel against PyPI's hashes and provenance | `command` / `verified` |
| `handlers register\|unregister\|status` | this user's `.lsd` file and `lsd://` link associations, no administrator: they run `lsdtools-gui` (the wheel's windowless entry point) with these global options, except that on Windows a home whose runtime store is its own (no `--store`) opens a double-clicked project in its default runtime's `LSDDesktop.exe "%1"` directly, with no lsdtools process before the window; `setup`, `runtime default` and `runtime remove` re-point it when that default changes. The home records the `lsdtools-gui` command line (`lsdtools-handlers-v1.json`), which a window starts for a project pinned to a runtime the home lacks. Windows: `HKEY_CURRENT_USER\Software\Classes` (`.lsd` -> `LSD.Project`, the `lsd` URL protocol) and a Start menu shortcut; Linux: an XDG desktop entry and MIME type set as their default; macOS: `platform_unavailable` until its application bundle. `unregister` removes only what names `lsdtools-gui` or a runtime store's Desktop | `files`, `links`, `opens`, `shortcut` / `removed[]` / what opens each now |

## Runtime commands (in the selected runtime)

| command | phase | does | `data` |
|---|---|---|---|
| `install REF... [-e] [--unreviewed] [--project P] [--require-attestation]`, `install --defaults` | P2 (`--project`: P3; `--require-attestation`: P5; `--defaults`: P6) | install packages (package references, below); `--defaults` alone: each default Core package (`lsd_packaging.default_packages`) not installed yet, one the catalog does not offer this account a `default_skipped` warning (`data.skipped[]`). A paid package gets this device's licence first, before any bytes move: offline for a one-time purchase (activated once, never asked again), online for a subscription or the publisher's own builds (renewed while it is owned). Exits 77 for what only a person can do: sign in (`lsdtools login`), buy it (the hint names its Store page), free a device (a licence holds three), or read an unreviewed URL; with `--project`, also pin them in P | `installed[]` (`name`, `version`, `lane`, `sha256`, and for a paid package `license` {`term`, `expires_at`}), `pinned[]` |
| `uninstall NAME...`, `list`, `update [NAME...]`, `info NAME` | P2 | the installed packages, and the catalog's; `update` moves installed catalog packages to their current versions (a local package changes where its folder does); a paid row of `list` carries this device's valid licence (`license` {`term`, `expires_at`}, null when none) | `removed[]` / `packages[]` / `updated[]`, `current[]` / `versions[]` |
| `content list [owner/name]`, `content install owner/name:ID\|FILE.lsdcontent`, `content remove owner/name:ID\|COORDINATE` | P6 | a package's data-only content packs (`.lsdcontent`: datasets, tutorials, demos, templates, assets, documentation). `list`: the installed packs, or the packs the catalog signs for one installed package version and which are installed; `install`: one optional pack of the installed version after checking its signed authority (a paid version's packs arrive sealed and open with this device's licence for it, acquired first), or a local file; `remove`: an optional pack (a required one leaves only with its package) | `content[]` / `installed`, `lane` / `removed` |
| `search TEXT` | P5 | the catalog's packages, from its signed index | `packages[]` |
| `new project DIR [--template ID\|owner/name:entry] [--open]` | P2 (entries: P3) | a new project from a template or an example, pinned to this runtime | `project`, `pinned`, `template`, `session` |
| `new package owner/name [--repo]` | P3 | a package source; `--repo` the whole repository layout (package-release-v1) | `path` |
| `templates`, `examples [owner/name] [--copy-to DIR]` | P2 (`examples`: P3) | what `new` and `open` can start from | `templates[]` / `examples[]` |
| `project check\|prepare\|pin\|packages P.lsd [--replace]` | P2 | validate, install what it pins, pin its runtime (`--replace`: move a project pinned to another runtime to this one, as `lsdtools --runtime SELECTOR project pin P --replace` does), list its packages | |
| `open P.lsd\|owner/name:entry [--copy-to DIR] [--window normal\|hidden] [--no-door] [--wait ready\|launched] [--timeout S]` | P2, P3 (entries, `--copy-to`: P3) | launch the Desktop of the project's pinned runtime (else the default) on it, detached, directly: no runtime command runs between. The window pins an unpinned project to its runtime (the warning says so), starts the project's Project Host, and has its runtime install what the host finds missing (`project prepare`); an error the window reports before it is ready ends the wait with `failed` (a hidden window is then closed). An entry opens a pinned working copy (edits commit themselves). Unless `--no-door`, the window gets a private action door and announces it (owner-only) in `<home>/native-sessions/<ui-pid>.json`; the session id is the window's UI process id. `--window hidden` (Windows; Linux P7): every surface of the window is cloaked by the compositor before it is first shown and never activates, so it draws and its snapshots work while nothing reaches the screen, the taskbar or the foreground; it needs its door | `session`, `window_pid`, `project`, `pinned`, `door{endpoint}`, `log`, `window` |
| `host P.lsd [--stop-when-idle] [--timeout S]` | P2 | the project's headless Project Host, pinned and prepared as `open` does; reports the one already hosting it | `session`, `project`, `started`, `pinned`, `acquired` |
| `sessions` | P2 | the windows with doors, and the Project Hosts, running in this home | `windows[]`, `hosts[]` |
| `close [SESSION]`, `logs [SESSION]` | P2 | close a window (Autosave has committed its edits; exit 75 while a question waits), or read its log | `closed` / `log`, `errors` |
| `reload [SESSION] [--window normal\|hidden]` | P3 | close the window (its edits are already saved) and, once its Project Host has left, open the project again: package code that changed since (a linked package's source, an `update`) loads | as `open`, and `reloaded` |
| `action SESSION KIND [-p KEY=VALUE]...` | P2 | one stable action over the session's door; a value is JSON, or else text | `session`, `kind`, `result` |
| `run P.lsd [--entity ID\|NAME [--with-upstream]] [--no-resume] [--parallel N]` | P2 | install what the project's graphs need, then run its pipelines headless under its editor lease (exit 73 while a window has it open); the pipelines run without the acquisition grant | `project`, `acquired`, `report` (each entity's status, rows and steps, with their errors) |
| `play P.lsd [--composition ID] --steps N [--snapshot-every N --out DIR] [--headless]` | P3 | step a composition natively and report its state hashes | `steps`, `state_sha256[]` |
| `snapshot [SESSION] [--view ID] [--location ID] --out FILE.png` | P2 (`P.lsd`: P3) | a picture of the window (`snapshot_ui`) or of one view (`view_snapshot`), through the app's own render path, never the screen | `path`, `width`, `height`, `bytes`, `session` |
| `export P.lsd --target windows-x86_64\|linux-x86_64\|android\|source --out DIR`, `export verify DIR` | P3 | an exported player | `path` |
| `python [-c CMD\|-m MOD\|SCRIPT\|-] [ARG]...` | P0 (`dev run`), P2 | python's own command line inside the runtime: its argv, `sys.path[0]`, working directory and exit status (apps/cli/src/lsd_cli/python_cmd.py) | |
| `test [PATH] [-- PYTEST ARGS]` | P3 | pytest from the `devtools` component | |
| `package lint\|prepare\|content build\|build-natives\|release` | P3, P5 | author a package; `build-natives` needs the `toolchain` component | |
| `mcp [--project P\|--attach SESSION\|latest] [--window] [--keep-open] [--timeout S]` | P2, P3 (`mcp probe`, `mcp doctor`: P3) | an MCP server on stdio (below); the windows it opens are hidden unless `--window` | |
| `login [--device]`, `logout`, `whoami` | P2 | a person signs in to the target's server: `login` opens its approval page (the one browser lsdtools opens), `--device` prints the address and code on stderr instead; `whoami` answers `signed_in` false rather than failing | `signed_in`, `account`, `entitlements[]` |
| `desktop` | P6 | start this runtime's start screen (`LSDDesktop --mode start`): recent projects, new from a template, open, the default packages, the account | `pid` |
| `join LINK` | P6 | join a shared session from its invite (`lsd://join/<token>`, its web `/join/<token>` link, or the token), as the Hub did: redeem it once and observe the session's exact runtime and package requirements, prepare the packages, then start a Desktop window with the private handoff in its environment (`LSD_NATIVE_REMOTE_HANDOFF_V1`), never its command line. Exit 77 when no one is signed in; a host on another runtime is exit 69 with `data.runtime_required` (the selector `lsdtools --runtime` takes, which installs it; `lsdtools-gui` retries with it) | `window_pid`, `project_id` |
| `handle-url URL [--yes]` | P6 | what an `lsd://` link asks, checked (`lsd://join/<token>`; `lsd://store/<owner>/<name>?action=select&version=V`; `lsd://store/open?packages=<owner/name@V>,...`; anything else is `invalid_data`). A link comes from any web page, so without `--yes` it only answers `action` and the `question` to ask; `lsdtools-gui` asks the person, then runs it with `--yes`, which joins or installs | `action`, `packages[]`, `question`, `done`, `installed[]` / `window_pid` |
| `commands` | P2 | the commands this runtime implements | `commands[]` (`name`, `summary`, `package_command`, `stream`) |
| `session prepare --requirements FILE` | P2 | the Desktop's own: a guest window acquires its collaboration session's packages through it | `readiness` |

### Package references

| reference | lane |
|---|---|
| `owner/name`, `owner/name@x.y.z` | the signed catalog |
| `https://github.com/owner/name`, `...@vX.Y.Z`, `.../releases/tag/vX.Y.Z` | a GitHub release (package-release-v1); `--unreviewed` unless the catalog lists the owner |
| `https://.../file.zip --sha256 HEX` | one source archive pinned by digest; `--unreviewed` |
| `./dir` | a copy of a source package directory |
| `-e ./dir` | linked by reference, never copied, not portable |

An **entry** `owner/name:ID` names an example the installed package carries (its release document's
`examples[].id`) or a template it declares.

### Runtime selection

1. `--runtime`.
2. The project's exact `desktop_runtime` pin, installed when missing. A revoked pin is refused online
   (exit 77, unless `--allow-revoked`) and used with a warning offline.
3. The home's default runtime.
4. An implicit `setup` from the track's signed head (unless `--no-auto-setup` or `--offline`).

### Launching

A runtime is verified when it is installed and trusted at launch: the outer half reads its ledger row
and manifest and finds its files (runtime-store-v1 `launch`; `runtime verify` re-checks them), then
starts the child with a scrubbed environment (Windows: in a job object that kills the command with
lsdtools; POSIX: `execve`). A window or Project Host a command starts is detached and leaves that job
(the job permits breakaway), so `open` returns once the window is ready (`--wait ready`) or launched,
and the window stays.

### MCP

`lsdtools mcp` is one agent's MCP server for this home's windows (`lsd_mcp.sessions`), on stdio
only: it installs packages, opens projects and runs pipelines with the user's authority, so it never
listens on a port any local process could reach. It starts unattached; with `--project` it opens that project and attaches, with `--attach`
it attaches to that window, and with neither it attaches to the home's only live window (never
guessing between several).

- **Lifecycle tools.** `lsd_status`, `lsd_open_project`, `lsd_new_project`, `lsd_attach`,
  `lsd_close`, `lsd_reload`, `lsd_install`, `lsd_packages`, `lsd_templates` and `lsd_run`. Each one that changes
  something runs this runtime's own command (`open`, `new project`, `install`, `close`, `run`, ...) in
  a process of its own and returns that command's `lsdtools.result.v1` document. A tool means what its
  command means, a package command's acquisition grant never reaches the server, and nothing an agent
  types is read as an option (paths are made absolute, references cannot start with `-`). A
  needs-human step stays one: `lsd_install` has no `--unreviewed`.
- **The window's tools.** While attached, the window's live action catalog is listed as `ui_*` tools,
  forwarded through the private door the window announced (`<home>/native-sessions/`), as `lsd-mcp
  serve` forwards them. Attaching, switching and losing a window send
  `notifications/tools/list_changed`; `lsd_action {kind, params}` sends the same actions for a client
  that has not listed them again. `skill` serves the in-app agent's procedure manuals.
- **Hidden windows.** The windows the server opens are hidden (`open --window hidden`) unless it runs
  with `--window` or a call passes `window: normal`: an agent works without putting windows on the
  person's screen, and sees them through `ui_snapshot_ui`.
- **Closing.** Windows the server opened close with it (their edits are already committed) unless
  opened with `keep_open` or the server runs with `--keep-open`; a window it attached to but did not
  open is left alone. The door token stays in the server: never in an argument, a result or a log.
- **Later (P3).** With no runtime installed, the outer half serves `lsd_status` and `lsd_guide`
  itself; `lsd_play` and project snapshots arrive with `play` and `snapshot P.lsd`.
