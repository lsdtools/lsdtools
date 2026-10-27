"""Canonical JSON (what every signature covers), strict JSON reading and file digests.

Canonical bytes are runtime-store-v1 ``canonical_json``: sorted keys, no whitespace, UTF-8, no NaN.
Strict reading refuses duplicate keys, non-finite numbers, invalid UTF-8 and anything over its bound.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from .errors import ManagerError

__all__ = ["canonical_bytes", "sha256_bytes", "sha256_file", "strict_loads"]

_CHUNK = 1 << 20


def canonical_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ManagerError("invalid_data", f"a value has no canonical JSON form: {exc}") from None
    return text.encode("utf-8")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate member {key!r}")
        result[key] = value
    return result


def _finite_only(value: str) -> Any:
    raise ValueError(f"non-finite number {value!r}")


def strict_loads(raw: bytes, *, maximum: int, label: str) -> Any:
    """``raw`` as strict JSON, or ``invalid_data`` naming ``label``."""
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise ManagerError("invalid_data", f"{label} is empty or larger than {maximum} bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_finite_only)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ManagerError("invalid_data", f"{label} is not strict UTF-8 JSON: {exc}") from None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()
