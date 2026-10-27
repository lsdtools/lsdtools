"""GET-only HTTPS to one server target: strict JSON answers and resumable, digest-checked artifacts.

No redirect is followed and no answer is cached: the target's origin is the only authority. A JSON
answer must be ``200 application/json``, uncompressed and at most 1 MiB. An artifact download is pinned
to ``<origin>/updates/v1/artifacts/<id>/download``, resumes with ``Range`` from a ``.part`` file, and is
accepted only at the signed manifest's exact size and sha256.

TLS trusts the platform's store (on Windows, its certificate store, so a corporate CA works). An
``HTTPS_PROXY`` (``http://[user:password@]host:port``) is tunnelled through with CONNECT unless
``NO_PROXY`` names the host.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import os
import re
import socket
import ssl
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Callable

from .canonical import strict_loads
from .errors import ManagerError
from .paths import long_path
from .targets import Target

__all__ = ["MAX_JSON_BYTES", "Transport"]

MAX_JSON_BYTES = 1 << 20
_TIMEOUT = 30.0
_CHUNK = 1 << 20
_ARTIFACT_PATH = re.compile(r"/updates/v1/artifacts/[0-9a-f]{32}/download")
_CONTENT_RANGE = re.compile(r"bytes (\d+)-(\d+)/(\d+)")
_USER_AGENT = "lsdtools/1"


def _tls_context() -> ssl.SSLContext:
    if not sys.platform.startswith("win"):
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    certificates = []
    for store in ("ROOT", "CA"):
        for certificate, encoding, trust in ssl.enum_certificates(store):
            if encoding == "x509_asn" and (trust is True or (
                    isinstance(trust, (set, frozenset)) and ssl.Purpose.SERVER_AUTH.oid in trust)):
                certificates.append(ssl.DER_cert_to_PEM_cert(certificate))
    if certificates:
        context.load_verify_locations(cadata="".join(certificates))
    else:
        context.load_default_certs()
    return context


def _proxy_for(host: str) -> tuple[str, int, str | None] | None:
    raw = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not raw:
        return None
    for entry in (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "").split(","):
        entry = entry.strip().lstrip(".").lower()
        if entry == "*" or (entry and (host.lower() == entry or host.lower().endswith("." + entry))):
            return None
    parsed = urllib.parse.urlsplit(raw if "://" in raw else "http://" + raw)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ManagerError("usage", "HTTPS_PROXY must be http://[user:password@]host:port")
    credentials = None
    if parsed.username is not None:
        token = f"{urllib.parse.unquote(parsed.username)}:{urllib.parse.unquote(parsed.password or '')}"
        credentials = "Basic " + base64.b64encode(token.encode("utf-8")).decode("ascii")
    return parsed.hostname, parsed.port or 8080, credentials


class Transport:
    """Requests to one target's origin. ``connection_factory`` replaces the network in tests."""

    def __init__(self, target: Target, *, connection_factory: Callable[[], Any] | None = None,
                 timeout: float = _TIMEOUT) -> None:
        self.target = target
        origin = urllib.parse.urlsplit(target.origin)
        self._scheme, self._host, self._port = origin.scheme, origin.hostname or "", origin.port
        self._netloc = origin.netloc
        self._factory = connection_factory
        self._timeout = timeout
        if self._scheme == "http" and not target.loopback:
            raise ManagerError("trust", f"{target.origin} is plain HTTP and not loopback")

    def _connection(self):
        if self._factory is not None:
            return self._factory()
        if self._scheme == "http":
            return http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
        proxy = _proxy_for(self._host)
        if proxy is None:
            return http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout,
                                               context=_tls_context())
        host, port, credentials = proxy
        connection = http.client.HTTPSConnection(host, port, timeout=self._timeout, context=_tls_context())
        connection.set_tunnel(self._host, self._port or 443,
                              headers={"Proxy-Authorization": credentials} if credentials else None)
        return connection

    def _unreachable(self, path: str, exc: BaseException) -> ManagerError:
        detail = " ".join(str(exc).split())[:200] or type(exc).__name__
        if isinstance(exc, ssl.SSLCertVerificationError):
            # Retrying cannot help: this Python cannot verify the server's certificate.
            return ManagerError("trust", f"{self.target.origin}'s certificate does not verify here: {detail}",
                                hint="install this Python's certificate authorities (macOS python.org: run "
                                     "'Install Certificates.command'), or point SSL_CERT_FILE at a CA bundle")
        return ManagerError("temporary", f"{self.target.origin} did not answer {path}: {detail}",
                            hint="check the network (or --offline), then retry")

    def get_json(self, path: str) -> dict:
        """One origin-relative ``path`` (with its query) as a strict JSON object."""
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
            raise ManagerError("internal", f"not an origin-relative path: {path!r}")
        connection = self._connection()
        try:
            connection.request("GET", path, headers={"Accept": "application/json",
                                                     "Accept-Encoding": "identity", "User-Agent": _USER_AGENT})
            response = connection.getresponse()
            if response.status != 200:
                code = "not_found" if response.status == 404 else (
                    "temporary" if response.status in (429, 502, 503, 504) else "protocol")
                raise ManagerError(code, f"{self.target.origin} answered HTTP {response.status} for {parsed.path}")
            media = str(response.getheader("Content-Type") or "").partition(";")[0].strip().lower()
            if media != "application/json" or (response.getheader("Content-Encoding") or "identity") != "identity":
                raise ManagerError("protocol", f"{parsed.path} did not answer uncompressed application/json")
            raw = response.read(MAX_JSON_BYTES + 1)
        except ManagerError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise self._unreachable(parsed.path, exc) from None
        finally:
            connection.close()
        document = strict_loads(raw, maximum=MAX_JSON_BYTES, label=f"{parsed.path}'s answer")
        if type(document) is not dict:
            raise ManagerError("protocol", f"{parsed.path} did not answer a JSON object")
        return document

    def artifact_path(self, url: str) -> str:
        """``url``'s path, if it is this origin's artifact download route; ``trust`` otherwise."""
        parsed = urllib.parse.urlsplit(url) if type(url) is str else None
        if (parsed is None or parsed.scheme != self._scheme or parsed.netloc != self._netloc
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or _ARTIFACT_PATH.fullmatch(parsed.path) is None):
            raise ManagerError("trust", f"an artifact URL leaves {self.target.origin}'s download route: {url!r}")
        return parsed.path

    def download(self, url: str, part: Path, *, size: int, sha256: str,
                 progress: Callable[[int, int], None] | None = None) -> Path:
        """Fetch ``url`` into ``part`` (resuming it) and return it once its size and sha256 are exact."""
        path = self.artifact_path(url)
        digest = hashlib.sha256()
        have = 0
        target = long_path(part)
        if os.path.exists(target):
            have = os.path.getsize(target)
            if have > size:
                os.remove(target)
                have = 0
            else:
                with open(target, "rb") as existing:
                    for chunk in iter(lambda: existing.read(_CHUNK), b""):
                        digest.update(chunk)
        if have < size:
            have, digest = self._fetch(path, target, have, size, digest, progress)
        if have < size:
            raise ManagerError("temporary", f"{path} ended after {have} of {size} bytes; the rest resumes",
                               hint="retry: the download continues where it stopped")
        if digest.hexdigest() != sha256:
            os.remove(target)
            raise ManagerError("trust", f"{path} delivered {have} bytes that are not the signed artifact")
        return part

    def _fetch(self, path, target, have, size, digest, progress):
        headers = {"Accept-Encoding": "identity", "User-Agent": _USER_AGENT}
        if have:
            headers["Range"] = f"bytes={have}-"
        connection = self._connection()
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            if response.status == 200 and have:
                have, digest = 0, hashlib.sha256()  # the server ignored the range: start over
            elif response.status == 206 and have:
                match = _CONTENT_RANGE.fullmatch(str(response.getheader("Content-Range") or ""))
                if match is None or (int(match[1]), int(match[2]), int(match[3])) != (have, size - 1, size):
                    raise ManagerError("protocol", f"{path} answered a range that is not the one asked for")
            elif response.status != 200:
                raise ManagerError("temporary" if response.status in (429, 502, 503, 504) else "protocol",
                                   f"{self.target.origin} answered HTTP {response.status} for {path}")
            if (response.getheader("Content-Encoding") or "identity") != "identity":
                raise ManagerError("protocol", f"{path} answered compressed bytes")
            with open(target, "r+b" if have else "wb") as output:
                output.seek(have)
                output.truncate()
                while True:
                    chunk = response.read(_CHUNK)
                    if not chunk:
                        break
                    have += len(chunk)
                    if have > size:
                        raise ManagerError("trust", f"{path} delivered more than the signed {size} bytes")
                    output.write(chunk)
                    digest.update(chunk)
                    if progress is not None:
                        progress(have, size)
                output.flush()
                os.fsync(output.fileno())
        except ManagerError:
            raise
        except (OSError, http.client.HTTPException, socket.timeout) as exc:
            raise self._unreachable(path, exc) from None
        finally:
            connection.close()
        return have, digest
