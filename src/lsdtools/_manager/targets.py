"""The server targets a wheel trusts: each one's origin, release track and signing keys, baked at build.

``targets_v1.json`` carries public facts only. lsd-installer's ``server-targets.json`` is their
authority, and its tests hold this copy equal to it. A target's keys are a set (the current key and,
during a rotation, the next), so a store signed under the current key stays valid across a rotation.

A target may also name artifact mirrors: URL templates tried, in order, before the origin's own download
route. A mirror only carries bytes; every download is held to the signed manifest's exact size and sha256,
whichever host served it (mirrors.MIRROR_HOSTS).
"""
from __future__ import annotations

import json
import os
import re
from typing import NamedTuple

from .ed25519 import key_id
from .errors import ManagerError
from .mirrors import require_mirror_template

__all__ = ["TARGET_NAMES", "Target", "get_target"]

TARGET_NAMES = ("production", "development")
_KEY_RE = re.compile(r"[0-9a-f]{64}")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})


class Target(NamedTuple):  # a NamedTuple: a launch imports no dataclasses (and inspect)
    name: str
    origin: str
    consumption_track: str
    updates_public_keys: tuple[str, ...]
    catalog_public_keys: tuple[str, ...]
    #: URL templates over {product}, {version} and {artifact_sha256}, tried before the origin.
    artifact_mirrors: tuple[str, ...] = ()

    @property
    def updates_keys(self) -> dict[str, str]:
        """key id -> public key."""
        return {key_id(key): key for key in self.updates_public_keys}

    @property
    def catalog_keys(self) -> dict[str, str]:
        return {key_id(key): key for key in self.catalog_public_keys}

    @property
    def loopback(self) -> bool:
        return self.origin.startswith("http://") and self.origin[len("http://"):].rsplit(":", 1)[0] in _LOOPBACK_HOSTS


def _load() -> dict[str, Target]:
    with open(os.path.join(os.path.dirname(__file__), "targets_v1.json"), encoding="utf-8") as handle:
        document = json.load(handle)
    if document.get("schema_version") != 1 or set(document.get("targets", {})) != set(TARGET_NAMES):
        raise ManagerError("internal", "this wheel's targets_v1.json is malformed")
    result = {}
    for name, value in document["targets"].items():
        keys = tuple(value["updates_public_keys"]), tuple(value["catalog_public_keys"])
        if not all(keys) or not all(_KEY_RE.fullmatch(key) for group in keys for key in group):
            raise ManagerError("internal", f"this wheel's {name} target has malformed keys")
        target = Target(name, value["origin"].rstrip("/"), value["consumption_track"], *keys)
        mirrors = value.get("artifact_mirrors", [])
        if type(mirrors) is not list or not all(type(template) is str for template in mirrors):
            raise ManagerError("internal", f"this wheel's {name} target has malformed artifact mirrors")
        for template in mirrors:
            require_mirror_template(template, loopback=target.loopback)
        result[name] = target._replace(artifact_mirrors=tuple(mirrors))
    if not result["production"].origin.startswith("https://"):
        raise ManagerError("internal", "the production target must be HTTPS")
    if not (result["development"].origin.startswith("https://") or result["development"].loopback):
        raise ManagerError("internal", "the development target must be HTTPS or loopback")
    return result


_TARGETS: dict[str, Target] | None = None


def get_target(name: str) -> Target:
    global _TARGETS
    if _TARGETS is None:
        _TARGETS = _load()
    try:
        return _TARGETS[name]
    except KeyError:
        raise ManagerError("usage", f"unknown target {name!r}: use {' or '.join(TARGET_NAMES)}") from None
