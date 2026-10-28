"""Check a package index serves exactly the release: each file's sha256 as release/<version>.json names it,
and, on PyPI, its attestation names this repository's release workflow as the publisher.

    python tools/check_index.py https://pypi.org VERSION

An index may take a moment to list a new upload: this reads it again for up to five minutes, the one
wait it has, because the upload's own job already finished. Standard library only.
"""
import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "lsdtools/lsdtools"
WORKFLOW = "release.yml"


def _json(url: str):
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "lsdtools-release"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def main(argv=None) -> int:
    index, version = (sys.argv[1:] if argv is None else argv)[:2]
    index = index.rstrip("/")
    record = json.loads((ROOT / "release" / f"{version}.json").read_text("utf-8"))
    expected = {row["filename"]: row["sha256"] for row in record["files"]}
    deadline = time.monotonic() + 300
    while True:
        try:
            listed = {row["filename"]: row["digests"]["sha256"]
                      for row in _json(f"{index}/pypi/lsdtools/{version}/json")["urls"]}
        except OSError as exc:
            listed = {"error": str(exc)}
        if listed == expected:
            break
        if time.monotonic() > deadline:
            print(f"{index} serves {json.dumps(listed, sort_keys=True)}, not {json.dumps(expected, sort_keys=True)}",
                  file=sys.stderr)
            return 1
        time.sleep(15)  # the index lists an upload a little after it accepted it
    for filename in sorted(expected):
        provenance = _json(f"{index}/integrity/lsdtools/{version}/{filename}/provenance")
        publishers = [bundle.get("publisher") or {} for bundle in provenance.get("attestation_bundles", [])]
        if not any(row.get("kind") == "GitHub" and row.get("repository") == REPOSITORY
                   and row.get("workflow") == WORKFLOW for row in publishers):
            print(f"{filename}'s attestation does not name {REPOSITORY} {WORKFLOW}: {publishers}", file=sys.stderr)
            return 1
        print(f"{expected[filename]}  {filename}  attested by {REPOSITORY} {WORKFLOW}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
