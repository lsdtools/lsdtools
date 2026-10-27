"""Check this tree is exactly what lsd-product generated: every file PROVENANCE.json names, with its sha256,
and nothing else (beyond .git/, dist/ and release/, which hold the checkout, a build and release records).

    python tools/check_provenance.py

The repository is a one-way export: a file changed here, or added here, fails this check and the release.
Fix it in lsd-product (lsdtools/wheel/generate.py and what it reads), then export again. Standard library only.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTSIDE = (".git", "dist", "release")


def main() -> int:
    provenance = json.loads((ROOT / "PROVENANCE.json").read_text("utf-8"))
    if provenance.get("schema") != "lsdtools.provenance.v1" or provenance.get("dirty") is not False:
        print("PROVENANCE.json is not a clean lsdtools.provenance.v1 export", file=sys.stderr)
        return 1
    expected = provenance["files"]
    problems = []
    for name, digest in sorted(expected.items()):
        path = ROOT / name
        if not path.is_file():
            problems.append(f"missing: {name}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            problems.append(f"changed: {name}")
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if path.is_file() and relative.parts[0] not in OUTSIDE and "__pycache__" not in relative.parts \
                and relative.as_posix() not in expected and relative.as_posix() != "PROVENANCE.json":
            problems.append(f"not exported: {relative.as_posix()}")
    if problems:
        print("this tree is not lsd-product's export at " + provenance["commit"] + ":\n  " + "\n  ".join(problems),
              file=sys.stderr)
        return 1
    print(f"{len(expected)} files are lsd-product {provenance['commit']}'s export of lsdtools {provenance['version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
