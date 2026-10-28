"""Artifact mirrors: where a target's runtime bytes may also come from (GitHub Releases), and nothing else.

A mirror only carries bytes. Every download, from a mirror or the origin, is held to the signed manifest's
exact size and sha256 (transport), so a mirror can make an install slower or fall back, never different.
Import-light: a launch reads its target, which names its mirrors.
"""
from __future__ import annotations

import re
import urllib.parse

from .errors import ManagerError

__all__ = ["MIRROR_HOSTS", "allowed_mirror", "mirror_url", "require_mirror_template"]

#: Where an artifact mirror may serve from: GitHub Releases and the hosts its downloads redirect to.
MIRROR_HOSTS = frozenset({"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"})
_FIELDS = ("product", "version", "artifact_sha256")


def allowed_mirror(parsed: urllib.parse.SplitResult, *, loopback: bool) -> bool:
    """HTTPS on a mirror host, without credentials; plain loopback HTTP only for a loopback target."""
    if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
        return False
    if parsed.scheme == "https":
        return parsed.hostname.lower() in MIRROR_HOSTS
    return loopback and parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")


def require_mirror_template(template: str, *, loopback: bool) -> str:
    """``template``, if it is an artifact mirror a target may name; ``internal`` otherwise."""
    fields = set(re.findall(r"{([^{}]*)}", template))
    valid = fields <= set(_FIELDS) and "artifact_sha256" in fields
    parsed = urllib.parse.urlsplit(template.format(**{name: "x" for name in _FIELDS})) if valid else None
    if parsed is None or parsed.query or not allowed_mirror(parsed, loopback=loopback):
        raise ManagerError("internal", f"not an artifact mirror a target may name: {template!r}")
    return template


def mirror_url(template: str, coordinate: dict) -> str:
    """The artifact ``coordinate``'s URL on the mirror ``template``."""
    return template.format(**{name: urllib.parse.quote(str(coordinate[name]), safe="") for name in _FIELDS})
