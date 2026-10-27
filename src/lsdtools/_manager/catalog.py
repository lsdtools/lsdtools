"""The signed Updates catalog: the target's trust anchors, then exact Base and Desktop releases.

Every answer is checked before a row is used:
- the signing-key endpoints must name keys this wheel trusts for the target (else ``trust``);
- a catalog page must have its exact fields, echo a fresh nonce inside a window of at most 600 seconds,
  and carry a valid Ed25519 signature over its canonical bytes;
- each row's manifest must carry its own valid signature, match the runtime-store-v1 manifest exactly,
  and name this platform; its artifact URL must be the origin's download route;
- only a row the catalog lists as ``available`` on a track the requested one consumes is returned.
Pages come newest first and continue with ``before_version`` (``next_version``).
"""
from __future__ import annotations

import json
import re
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

from .canonical import canonical_bytes
from .ed25519 import key_id, verify
from .errors import ManagerError
from .manifests import (  # noqa: F401  (re-exported: the checks a release must pass)
    _COORDINATE_FIELDS, _HEX32, _HEX64, _coordinate, _positive, _sha, _version, check_base_manifest,
    check_runtime_manifest, platform_row, version_key,
)
from .targets import Target

if TYPE_CHECKING:  # the network modules load only for a command that reaches the server
    from .transport import Transport

__all__ = ["CatalogRow", "Catalog", "Trust", "platform_row"]

_HEX16 = re.compile(r"[0-9a-f]{16}")
_ELIGIBLE = {"prod": frozenset({"prod"}), "beta": frozenset({"prod", "beta"}),
             "alpha": frozenset({"prod", "beta", "alpha"})}
_PAGE = 20
_MAX_NOTES = 20_000



@dataclass(frozen=True)
class Trust:
    updates: dict  # key id -> public key, the subset of the target's keys the server signs with now
    catalog: dict


@dataclass(frozen=True)
class CatalogRow:
    """One verified release: its manifest (and the exact bytes its signature covers) and download URL."""

    product: str
    manifest: dict
    signature: dict
    url: str
    channel: dict
    notes: str

    @property
    def coordinate(self) -> dict:
        return self.manifest["coordinate"]

    @property
    def manifest_bytes(self) -> bytes:
        return canonical_bytes(self.manifest)


class Catalog:
    """The target's catalog, read through one transport for one platform and track."""

    def __init__(self, transport: Transport, *, system: str, arch: str, track: str | None = None,
                 clock=time.time, nonce=lambda: secrets.token_hex(16)) -> None:
        self.transport = transport
        self.target: Target = transport.target
        self.system, self.arch = system, arch
        self.track = track or self.target.consumption_track
        if self.track not in _ELIGIBLE:
            raise ManagerError("usage", f"unknown track {self.track!r}: use {', '.join(_ELIGIBLE)}")
        self._platform: dict | None = None
        self._clock, self._nonce = clock, nonce
        self._trust: Trust | None = None

    @property
    def platform(self) -> dict:
        """This platform's runtime-platforms-v1 row, looked up when a runtime is wanted: the server's
        trust does not depend on it, so it is checked on a platform LSD has no runtime for yet too."""
        if self._platform is None:
            self._platform = platform_row(self.system, self.arch)
        return self._platform

    def trust(self) -> Trust:
        """The server's current Updates and Catalog keys, each one this wheel trusts for the target."""
        if self._trust is None:
            found = {}
            for name, path, trusted in (("Updates", "/updates/v1/signing-key", self.target.updates_keys),
                                        ("Catalog", "/catalog/v1/signing-key", self.target.catalog_keys)):
                document = self.transport.get_json(path)
                if set(document) != {"algorithm", "key_id", "public_key"} or document["algorithm"] != "ed25519":
                    raise ManagerError("protocol", f"{path} violates its v1 schema")
                public = document["public_key"]
                if type(public) is not str or not _HEX64.fullmatch(public) or document["key_id"] != key_id(public):
                    raise ManagerError("protocol", f"{path} names an inconsistent key")
                if trusted.get(document["key_id"]) != public:
                    raise ManagerError("trust", f"{self.target.origin} signs with a {name} key this lsdtools does "
                                       f"not trust for {self.target.name} ({document['key_id']})",
                                       hint="update lsdtools, or check that --target names this server")
                found[name] = {document["key_id"]: public}
            self._trust = Trust(found["Updates"], found["Catalog"])
        return self._trust

    def _verified(self, signed: dict, label: str) -> None:
        signature = signed.get("signature")
        keys = self.trust().updates
        if (type(signature) is not dict or set(signature) != {"algorithm", "key_id", "value"}
                or signature["algorithm"] != "ed25519" or signature["key_id"] not in keys):
            raise ManagerError("trust", f"{label} is not signed by the target's Updates key")
        verify(canonical_bytes({k: v for k, v in signed.items() if k != "signature"}), signature["value"],
               keys[signature["key_id"]])

    def _page(self, product: str, before: str | None) -> dict:
        collection = "runtimes" if product == "desktop" else "bases"
        nonce = self._nonce()
        query = ([("product", "desktop")] if product == "desktop" else []) + [
            ("platform", self.system), ("arch", self.arch), ("track", self.track), ("protocol", 1),
            ("nonce", nonce), ("limit", _PAGE)] + ([("before_version", before)] if before else [])
        path = ("/updates/v1/runtime-catalog?" if product == "desktop" else "/updates/v1/base-catalog?")
        document = self.transport.get_json(path + urllib.parse.urlencode(query))
        label = f"the {product} catalog"
        fields = {"protocol", "nonce", "issued_at", "expires_at", "product", "platform", "arch", "track",
                  "channel_head", collection, "next_version", "signature"}
        if (set(document) != fields or document["protocol"] != 1 or document["product"] != product
                or (document["platform"], document["arch"]) != (self.system, self.arch)
                or document["track"] != self.track):
            raise ManagerError("protocol", f"{label} violates its protocol-1 schema")
        now = int(self._clock())
        issued, expires = document["issued_at"], document["expires_at"]
        if (document["nonce"] != nonce or type(issued) is not int or type(expires) is not int
                or not 0 < issued < expires or expires - issued > 600 or issued > now + 30 or expires < now):
            raise ManagerError("trust", f"{label}'s answer is stale or not for this request",
                               hint="check this computer's clock")
        self._verified(document, label)
        if document["next_version"] is not None:
            _version(document["next_version"], f"{label}'s continuation")
        if type(document[collection]) is not list or len(document[collection]) > _PAGE:
            raise ManagerError("protocol", f"{label} returned more rows than asked for")
        return document

    def _row(self, product: str, raw) -> CatalogRow | None:
        label = f"a {product} catalog row"
        if type(raw) is not dict or set(raw) != {"manifest", "manifest_signature", "notes", "url", "channel"}:
            raise ManagerError("protocol", f"{label} violates its schema")
        channel = raw["channel"]
        if (type(channel) is not dict or set(channel) != {"track", "generation", "state"}
                or type(channel["generation"]) is not int or channel["generation"] <= 0):
            raise ManagerError("protocol", f"{label} has invalid channel metadata")
        if type(raw["notes"]) is not str or len(raw["notes"]) > _MAX_NOTES:
            raise ManagerError("protocol", f"{label}'s notes exceed their bound")
        check = check_runtime_manifest if product == "desktop" else check_base_manifest
        manifest = check(raw["manifest"], self.system, self.arch, self.platform)
        signature = raw["manifest_signature"]
        keys = self.trust().updates
        if (type(signature) is not dict or set(signature) != {"algorithm", "key_id", "value"}
                or signature["algorithm"] != "ed25519" or signature["key_id"] not in keys):
            raise ManagerError("trust", f"{label}'s manifest is not signed by the target's Updates key")
        verify(canonical_bytes(manifest), signature["value"], keys[signature["key_id"]])
        self.transport.artifact_path(raw["url"])
        if channel["state"] != "available" or channel["track"] not in _ELIGIBLE[self.track]:
            return None  # revoked, withdrawn or another track's: the download route would still serve it
        return CatalogRow(product, manifest, signature, raw["url"], channel, raw["notes"])

    def rows(self, product: str) -> Iterator[CatalogRow]:
        """Every available release of ``product`` ("desktop" or "base"), newest first."""
        collection = "runtimes" if product == "desktop" else "bases"
        before, seen = None, set()
        while True:
            document = self._page(product, before)
            for raw in document[collection]:
                row = self._row(product, raw)
                if row is not None:
                    yield row
            before = document["next_version"]
            if before is None or before in seen:
                return
            seen.add(before)

    def head(self) -> CatalogRow:
        """The track's current Desktop release."""
        document = self._page("desktop", None)
        head = document["channel_head"]
        if head is None:
            raise ManagerError("not_found", f"{self.target.origin} has no Desktop release on the {self.track} track")
        if type(head) is not dict or set(head) != {"version", "release_id", "artifact_sha256"}:
            raise ManagerError("protocol", "the Desktop catalog's channel head is invalid")
        for raw in document["runtimes"]:
            row = self._row("desktop", raw)
            if row is not None and all(row.coordinate[name] == head[name] for name in head):
                return row
        for row in self.rows("desktop"):
            if all(row.coordinate[name] == head[name] for name in head):
                return row
        raise ManagerError("not_found", "the Desktop channel head is not an available release")

    def select(self, selector: str) -> CatalogRow:
        """``latest``, ``x.y.z`` (its newest build) or ``x.y.z/<sha256 or a 12+ hex prefix>``."""
        if selector in ("latest", "", None):
            return self.head()
        version, _, prefix = selector.partition("/")
        _version(version, f"runtime selector {selector!r}")
        if prefix and (len(prefix) < 12 or not re.fullmatch(r"[0-9a-f]+", prefix)):
            raise ManagerError("usage", "a runtime selector's digest is 12 or more lowercase hex digits")
        matches = [row for row in self.rows("desktop") if row.coordinate["version"] == version
                   and row.coordinate["artifact_sha256"].startswith(prefix)]
        if not matches:
            raise ManagerError("not_found", f"no available Desktop {selector} on the {self.track} track")
        if prefix and len({row.coordinate["artifact_sha256"] for row in matches}) > 1:
            raise ManagerError("usage", f"{selector} matches more than one build: give more of its digest")
        return matches[0]

    def base_for(self, runtime: CatalogRow) -> CatalogRow:
        """The exact Base ``runtime`` was built over."""
        wanted = runtime.manifest["runtime_base"]
        for row in self.rows("base"):
            if all(row.coordinate[name] == wanted[name] for name in _COORDINATE_FIELDS) \
                    and row.manifest["tree_sha256"] == wanted["tree_sha256"]:
                return row
        raise ManagerError("not_found", f"Base {wanted['version']} for Desktop {runtime.coordinate['version']} is "
                           "not an available release")
