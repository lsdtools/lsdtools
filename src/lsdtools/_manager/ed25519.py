"""Strict Ed25519 verification in pure Python (RFC 8032), the way lsd-installer and the runtime's reader verify.

Beyond RFC 8032 it refuses a non-canonical point or scalar encoding and a public key or R that is not
of prime order, so one message has exactly one accepted signature per key.
"""
from __future__ import annotations

import base64
import binascii
import hashlib

from .errors import ManagerError

__all__ = ["key_id", "verify"]

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_MINUS_ONE = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)


def _x_from_y(y: int) -> int:
    square = (y * y - 1) * pow((_D * y * y + 1) % _P, _P - 2, _P) % _P
    x = pow(square, (_P + 3) // 8, _P)
    if (x * x - square) % _P:
        x = x * _SQRT_MINUS_ONE % _P
    if (x * x - square) % _P:
        raise ManagerError("trust", "an Ed25519 point is not on the curve")
    return x


def _decode_point(encoded: bytes, label: str) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise ManagerError("trust", f"the Ed25519 {label} is not 32 bytes")
    value = int.from_bytes(encoded, "little")
    sign, y = value >> 255, value & ((1 << 255) - 1)
    if y >= _P:
        raise ManagerError("trust", f"the Ed25519 {label} is not canonically encoded")
    x = _x_from_y(y)
    if (x & 1) != sign:
        x = _P - x
    if x == 0 and sign:
        raise ManagerError("trust", f"the Ed25519 {label} has a non-canonical sign bit")
    return x, y, 1, x * y % _P


def _add(left, right):
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * _D * t1 * t2 % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = (b - a) % _P, (d - c) % _P, (d + c) % _P, (b + a) % _P
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _multiply(scalar: int, point):
    result, addend = _IDENTITY, point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _equal(left, right) -> bool:
    return ((left[0] * right[2] - right[0] * left[2]) % _P == 0
            and (left[1] * right[2] - right[1] * left[2]) % _P == 0)


def _base_point():
    y = 4 * pow(5, _P - 2, _P) % _P
    x = _x_from_y(y)
    if x & 1:
        x = _P - x
    return x, y, 1, x * y % _P


_BASE = _base_point()


def _public_key_bytes(public_key_hex: str) -> bytes:
    if type(public_key_hex) is not str or len(public_key_hex) != 64:
        raise ManagerError("trust", "an Ed25519 public key is not 64 hex digits")
    try:
        return bytes.fromhex(public_key_hex)
    except ValueError:
        raise ManagerError("trust", "an Ed25519 public key is not hex") from None


def key_id(public_key_hex: str) -> str:
    """The first 16 hex of sha256 over the raw public key (runtime-store-v1)."""
    return hashlib.sha256(_public_key_bytes(public_key_hex)).hexdigest()[:16]


def verify(message: bytes, signature_base64: str, public_key_hex: str) -> None:
    """Return if ``signature_base64`` signs ``message`` under the key; raise ``trust`` otherwise."""
    if type(signature_base64) is not str:
        raise ManagerError("trust", "an Ed25519 signature is not canonical base64")
    try:
        signature = base64.b64decode(signature_base64.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ManagerError("trust", "an Ed25519 signature is not canonical base64") from None
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_base64:
        raise ManagerError("trust", "an Ed25519 signature is not canonical 64-byte base64")
    public = _public_key_bytes(public_key_hex)
    public_point = _decode_point(public, "public key")
    r_point = _decode_point(signature[:32], "signature point")
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _L:
        raise ManagerError("trust", "an Ed25519 signature scalar is not canonical")
    if (_equal(public_point, _IDENTITY)
            or not _equal(_multiply(_L, public_point), _IDENTITY)
            or not _equal(_multiply(_L, r_point), _IDENTITY)):
        raise ManagerError("trust", "an Ed25519 signature uses a point outside the prime-order group")
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    if not _equal(_multiply(scalar, _BASE), _add(r_point, _multiply(challenge, public_point))):
        raise ManagerError("trust", "an Ed25519 signature was rejected")
