"""The lsdtools manager: install exact signed LSD runtimes and start them. Stdlib and zstandard only.

``pip install lsdtools`` puts this package in the user's own Python, 3.10 or newer. It never imports the
engine and never runs pip. It sets up, verifies and launches runtimes; every other command runs inside
the selected runtime (``<runtime>/LSDCli.exe lsdtools <argv>``).

The store it writes is runtime-store-v1 (``base/packaging/contracts/runtime-store-v1.json``), its
platforms are runtime-platforms-v1, and its command line is lsdtools-cli-v1 (``lsdtools/docs/CLI.md``).
"""

#: The PyPI ``lsdtools`` release this manager is: it versions apart from the runtimes it installs.
VERSION = "1.0.0rc2"
