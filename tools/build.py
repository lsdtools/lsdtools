"""Build this tree's wheel and sdist with its own backend (tools/wheel_backend.py), into DIST.

    python tools/build.py [DIST]

The bytes are the tree's alone: the backend stores (never deflates) and stamps every member with the
tree's source_date_epoch, so any Python 3.10+ on any system builds the same wheel and sdist that
release/<version>.json names. Standard library only.
"""
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # nothing of this build is left in the tree
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import wheel_backend  # noqa: E402


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = Path(argv[0] if argv else "dist").resolve()
    out.mkdir(parents=True, exist_ok=True)
    for build in (wheel_backend.build_wheel, wheel_backend.build_sdist):
        print(out / build(str(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
