"""Check a build is the release: DIST's wheel and sdist have the sha256 release/<version>.json names, and the
tag is that version's.

    python tools/check_release.py DIST TAG

release/<version>.json is written when lsd-product's release is cut, from the build its local gate tested
(lsdtools.release.v1: the version, the export's commit, each file's name and sha256, and the gate receipts'
digests). A rebuild that differs means the tree or the backend is not what was tested: the release stops.
Standard library only.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None) -> int:
    dist, tag = (sys.argv[1:] if argv is None else argv)[:2]
    version = json.loads((ROOT / "wheel.json").read_text("utf-8"))["version"]
    if tag != f"v{version}":
        print(f"tag {tag} is not this tree's version v{version}", file=sys.stderr)
        return 1
    record = json.loads((ROOT / "release" / f"{version}.json").read_text("utf-8"))
    provenance = json.loads((ROOT / "PROVENANCE.json").read_text("utf-8"))
    if record.get("schema") != "lsdtools.release.v1" or record.get("version") != version \
            or record.get("commit") != provenance["commit"]:
        print(f"release/{version}.json does not describe this export", file=sys.stderr)
        return 1
    built = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in Path(dist).iterdir()
             if path.is_file()}
    expected = {row["filename"]: row["sha256"] for row in record["files"]}
    if built != expected:
        print("the build is not the tested release:\n  built    " + json.dumps(built, sort_keys=True)
              + "\n  expected " + json.dumps(expected, sort_keys=True), file=sys.stderr)
        return 1
    for name, digest in sorted(built.items()):
        print(f"{digest}  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
