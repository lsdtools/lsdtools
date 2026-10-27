"""The released lsdtools, tested as installed from its wheel (never from src/): the facade imports no engine, the
manager needs only the standard library and zstandard, its Ed25519 meets RFC 8032, and the command keeps
lsdtools-cli-v1's contract for everything it can do without a runtime. Standard library only.

    python -m pip install dist/lsdtools-*.whl && python -m unittest discover -s tests -v
"""
import base64
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STANDARD = set(getattr(sys, "stdlib_module_names", ())) | {"__main__", "_frozen_importlib", "_frozen_importlib_external"}


def _lsdtools(*argv, home=None):
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("LSD", "LSDTOOLS"))}
    if home is not None:
        environment["LSD_HOME"] = str(home)
    done = subprocess.run([sys.executable, "-c", "import sys; from lsdtools._manager.cli import main; "
                                                 "sys.exit(main(sys.argv[1:]))", *argv],
                          capture_output=True, text=True, env=environment, timeout=120)
    return done.returncode, done.stdout, done.stderr


class Installed(unittest.TestCase):
    def test_the_package_is_the_installed_wheel_not_the_tree(self):
        import lsdtools

        self.assertNotIn(ROOT / "src", Path(lsdtools.__file__).resolve().parents)

    def test_the_facade_names_the_sdk_and_imports_no_engine(self):
        import lsdtools

        self.assertEqual(lsdtools.__lsdtools_flavor__, "facade")
        self.assertIn("Tool", lsdtools.__all__)
        with self.assertRaises(lsdtools.RuntimeRequiredError) as raised:
            lsdtools.Tool
        self.assertIsInstance(raised.exception, ImportError)
        self.assertIn("lsdtools python", str(raised.exception))
        engine = [name for name in sys.modules if name == "lsd" or name.startswith(("lsd.", "lsd_"))]
        self.assertEqual(engine, [])

    def test_the_manager_needs_only_the_standard_library_and_zstandard(self):
        code = ("import sys, pkgutil, importlib, lsdtools._manager as m\n"
                "for info in pkgutil.iter_modules(m.__path__):\n"
                "    if info.name != '__main__':\n"  # importing it runs the command
                "        importlib.import_module('lsdtools._manager.' + info.name)\n"
                "print('\\n'.join(sorted({name.split('.')[0] for name in sys.modules})))")
        done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr)
        # What the interpreter loads before any lsdtools import is not lsdtools' own (Debian and Ubuntu
        # Pythons import a sitecustomize at startup).
        before = subprocess.run([sys.executable, "-I", "-c", "import sys; print(' '.join(sys.modules))"],
                                capture_output=True, text=True, timeout=120)
        startup = {name.split(".")[0] for name in before.stdout.split()}
        roots = set(done.stdout.split()) - STANDARD - startup - {"lsdtools", "zstandard"}
        self.assertEqual({root for root in roots if not root.startswith("_")}, set())


class Ed25519(unittest.TestCase):
    """RFC 8032, section 7.1: the manager verifies every signed manifest and catalog page with this."""

    VECTORS = (
        ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5"
         "f0595bbe24655141438e7a100b"),
        ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eae"
         "b4302aeeb00d291612bb0c00"),
    )

    def test_the_rfc_vectors_verify_and_any_change_does_not(self):
        from lsdtools._manager.ed25519 import verify

        for public, message, signature in self.VECTORS:
            signed = base64.b64encode(bytes.fromhex(signature)).decode("ascii")
            verify(bytes.fromhex(message), signed, public)
            changed = bytearray(bytes.fromhex(signature))
            changed[0] ^= 1
            with self.assertRaises(Exception):
                verify(bytes.fromhex(message), base64.b64encode(bytes(changed)).decode("ascii"), public)
            with self.assertRaises(Exception):
                verify(bytes.fromhex(message) + b"x", signed, public)


class CommandLine(unittest.TestCase):
    """lsdtools-cli-v1 without a runtime: one result document, its exit statuses, its guide."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="lsdtools-test-"))

    def _document(self, *argv, status=0):
        code, out, err = _lsdtools("--json", "--home", str(self.home), *argv, home=self.home)
        self.assertEqual(code, status, err)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 1, out)
        document = json.loads(lines[0])
        self.assertEqual(document["schema"], "lsdtools.result.v1")
        self.assertEqual(document["ok"], status == 0)
        return document

    def test_version_and_guide(self):
        code, out, _err = _lsdtools("--version")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("lsdtools "))
        self.assertIsNone(self._document("version")["data"]["default_runtime"])
        for topic in ("quickstart", "agents", "mcp", "projects", "packages", "json", "troubleshooting"):
            self.assertTrue(self._document("guide", topic)["data"]["text"])
        self.assertEqual(self._document("guide", "nothing", status=66)["error"]["code"], "not_found")

    def test_without_a_runtime_the_statuses_are_the_contracts(self):
        self.assertEqual(self._document("runtime", "path", status=66)["error"]["code"], "not_found")
        self.assertEqual(self._document("runtime", "list")["data"]["runtimes"], [])
        code, _out, _err = _lsdtools("--target")
        self.assertEqual(code, 2)

    def test_mcp_config_names_this_installation(self):
        config = self._document("mcp-config", "--client", "claude")["data"]["config"]["mcpServers"]["lsd"]
        self.assertTrue(Path(config["command"]).name.startswith("lsdtools"))
        self.assertEqual(config["args"][-1], "mcp")


if __name__ == "__main__":
    unittest.main()
