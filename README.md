# lsdtools

`lsdtools` installs exact, signed LSD runtimes on your computer and runs everything inside them:
projects, packages, scripts and the Desktop. It is built to be driven by an agent as easily as by a
person: every command can answer with one JSON document and a documented exit status, and nothing
prompts.

```
pip install lsdtools            # or: uv tool install lsdtools
lsdtools setup                  # install the current LSD runtime (once, per user, no admin)
lsdtools doctor                 # check Python, the server, the store and this platform
lsdtools python my_script.py    # run a script that imports lsdtools, inside that runtime
lsdtools --json runtime list    # one lsdtools.result.v1 document on stdout
```

## What this package is

- **The `lsdtools` command.** Its own code uses only the standard library and `zstandard`. It downloads
  runtimes from the signed LSD catalog, checks every signature and digest before a byte is extracted,
  and re-checks the runtime before every launch.
- **The SDK's names, for editors.** The SDK itself (`from lsdtools import Tool, Engine, Table`) runs
  inside an LSD runtime, the way a Blender script runs inside Blender. Imported in this Python, an SDK
  name raises `lsdtools.RuntimeRequiredError` (an `ImportError`) saying to run the script with
  `lsdtools python`.

## Exit statuses

| status | meaning |
|---|---|
| 0 | done |
| 1 | the operation failed |
| 2 | the command line is wrong |
| 65 | an input is malformed |
| 66 | not found |
| 69 | not available here (this platform, a component, offline) |
| 70 | a defect |
| 73 | exists, or in use |
| 75 | temporary: retry |
| 76 | a server or runtime answered outside its contract |
| 77 | a person must act |
| 78 | a signature, key or digest did not verify |

## Platforms

Windows x86_64 today; Linux x86_64 and macOS arm64 are planned. On a platform without a runtime,
the runtime commands exit 69 and say which platforms have one.

Licensed under Apache-2.0.
