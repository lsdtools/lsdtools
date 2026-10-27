"""The runtime-store-v1 manifests and the platform table: what a release must be, checked with the standard library.

A launch reads these checks (``Verify.ROW``), so they live apart from the network catalog (``catalog``), which
re-exports them, and import nothing the launch does not need.
"""
from __future__ import annotations

import json
import os
import re

from .errors import ManagerError

__all__ = ["check_base_manifest", "check_runtime_manifest", "platform_row", "version_key"]

_HEX32, _HEX64 = (re.compile(r"[0-9a-f]{%d}" % n) for n in (32, 64))
_VERSION = re.compile(r"(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})")
_MAX_ARCHIVE = 16 * 1024 ** 3
_COORDINATE_FIELDS = {"product", "version", "release_id", "artifact_sha256", "platform", "arch"}
_RUNTIME_FIELDS = {
    "schema_version", "coordinate", "runtime_base", "archive_format", "archive_size", "archive_tree_sha256",
    "payload_tree_sha256", "desktop_executable", "desktop_executable_sha256", "desktop_authenticode_verified",
    "cli_executable", "cli_executable_sha256", "cli_authenticode_verified", "app_bundle", "app_bundle_sha256",
    "project_schema_min", "project_schema_max", "published_at",
}
_BASE_FIELDS = {
    "schema_version", "coordinate", "archive_format", "archive_size", "tree_sha256", "python_version",
    "runtime_dependency_policy_sha256", "distributions", "published_at",
}


def platform_row(system: str, arch: str) -> dict:
    """This platform's runtime-platforms-v1 row; ``platform_unavailable`` unless it is available."""
    with open(os.path.join(os.path.dirname(__file__), "platforms_v1.json"), encoding="utf-8") as handle:
        table = json.load(handle)
    for row in table["platforms"]:
        if row["platform"] == system and row["arch"] == arch:
            if row["state"] != "available":
                available = ", ".join(r["id"] for r in table["platforms"] if r["state"] == "available")
                raise ManagerError("platform_unavailable", f"LSD runtimes for {row['id']} are {row['state']}",
                                   hint=f"available today: {available}")
            return row
    raise ManagerError("platform_unavailable", f"LSD has no runtime for {system}-{arch}")


def _version(value, label: str) -> str:
    match = _VERSION.fullmatch(value) if type(value) is str else None
    if match is None or int(match[1]) > 255 or int(match[2]) > 255 or int(match[3]) > 65535:
        raise ManagerError("protocol", f"{label} is not a canonical version")
    return value


def version_key(value: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in value.split("."))
    return major, minor, patch


def _coordinate(value, product: str, system: str, arch: str, label: str) -> dict:
    if (type(value) is not dict or set(value) != _COORDINATE_FIELDS or value["product"] != product
            or type(value.get("release_id")) is not str or not _HEX32.fullmatch(value["release_id"])
            or type(value.get("artifact_sha256")) is not str or not _HEX64.fullmatch(value["artifact_sha256"])):
        raise ManagerError("protocol", f"{label} has an invalid coordinate")
    _version(value["version"], f"{label}'s version")
    if (value["platform"], value["arch"]) != (system, arch):
        raise ManagerError("protocol", f"{label} is for {value['platform']}-{value['arch']}, not {system}-{arch}")
    return value


def _sha(value, label: str) -> None:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise ManagerError("protocol", f"{label} is not a sha256")


def _positive(value, maximum: int, label: str) -> None:
    if type(value) is not int or not 0 < value <= maximum:
        raise ManagerError("protocol", f"{label} is out of range")


def check_runtime_manifest(manifest, system: str, arch: str, platform: dict) -> dict:
    """``manifest`` if it is exactly a runtime-store-v1 runtime manifest for this platform."""
    label = "a runtime manifest"
    if type(manifest) is not dict or set(manifest) != _RUNTIME_FIELDS or manifest.get("schema_version") != 1:
        raise ManagerError("protocol", f"{label} violates runtime-store-v1")
    _coordinate(manifest["coordinate"], "desktop", system, arch, label)
    base = manifest["runtime_base"]
    if type(base) is not dict or set(base) != _COORDINATE_FIELDS | {"tree_sha256"}:
        raise ManagerError("protocol", f"{label} has an invalid runtime_base")
    _coordinate({k: v for k, v in base.items() if k != "tree_sha256"}, "base", system, arch, f"{label}'s base")
    _sha(base["tree_sha256"], f"{label}'s base tree")
    expected = {"archive_format": platform["runtime_archive_format"],
                "desktop_executable": platform["desktop_executable"],
                "cli_executable": platform["cli_executable"], "app_bundle": platform["app_bundle"]}
    if any(manifest[name] != value for name, value in expected.items()):
        raise ManagerError("protocol", f"{label} names files runtime-platforms-v1 does not give {system}-{arch}")
    for name in ("archive_tree_sha256", "payload_tree_sha256", "desktop_executable_sha256",
                 "cli_executable_sha256", "app_bundle_sha256"):
        _sha(manifest[name], f"{label}'s {name}")
    for name in ("desktop_authenticode_verified", "cli_authenticode_verified"):
        if type(manifest[name]) is not bool:
            raise ManagerError("protocol", f"{label}'s {name} is not a boolean")
    _positive(manifest["archive_size"], _MAX_ARCHIVE, f"{label}'s archive_size")
    _positive(manifest["published_at"], (1 << 63) - 1, f"{label}'s published_at")
    low, high = manifest["project_schema_min"], manifest["project_schema_max"]
    if type(low) is not int or type(high) is not int or not 1 <= low <= high <= 65535:
        raise ManagerError("protocol", f"{label}'s project schema range is invalid")
    return manifest


def check_base_manifest(manifest, system: str, arch: str, platform: dict) -> dict:
    label = "a Base manifest"
    if type(manifest) is not dict or set(manifest) != _BASE_FIELDS or manifest.get("schema_version") != 1:
        raise ManagerError("protocol", f"{label} violates runtime-store-v1")
    _coordinate(manifest["coordinate"], "base", system, arch, label)
    if manifest["archive_format"] != platform["base_archive_format"]:
        raise ManagerError("protocol", f"{label} has another archive format")
    _positive(manifest["archive_size"], _MAX_ARCHIVE, f"{label}'s archive_size")
    _positive(manifest["published_at"], (1 << 63) - 1, f"{label}'s published_at")
    _sha(manifest["tree_sha256"], f"{label}'s tree")
    _sha(manifest["runtime_dependency_policy_sha256"], f"{label}'s dependency policy")
    _version(manifest["python_version"], f"{label}'s Python version")
    names = [item.get("name") if type(item) is dict and set(item) == {"name", "version"} else None
             for item in manifest["distributions"]] if type(manifest["distributions"]) is list else [None]
    if not names or None in names or names != sorted(set(names)):
        raise ManagerError("protocol", f"{label}'s distributions are not a sorted unique list")
    return manifest
