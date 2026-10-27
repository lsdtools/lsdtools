"""One failure type with the exit status and error code lsdtools-cli-v1 gives each kind of failure."""
from __future__ import annotations

__all__ = ["EXIT_STATUS", "ManagerError"]

#: lsdtools-cli-v1 "Exit status": each error code and its status.
EXIT_STATUS = {
    "failed": 1,
    "usage": 2,
    "invalid_data": 65,
    "not_found": 66,
    "unavailable": 69,
    "platform_unavailable": 69,
    "component_missing": 69,
    "internal": 70,
    "exists": 73,
    "in_use": 73,
    "temporary": 75,
    "protocol": 76,
    "needs_human": 77,
    "trust": 78,
}


class ManagerError(Exception):
    """A failure the command line reports as ``{code, message, hint, retryable}`` and exits with.

    ``data`` is the failed command's own result when the failure has one (``run``'s report of each
    entity), reported as the document's ``data``; otherwise the document's ``data`` is ``null``."""

    def __init__(self, code: str, message: str, *, hint: str = "", retryable: bool | None = None,
                 data: dict | None = None) -> None:
        if code not in EXIT_STATUS:
            raise ValueError(f"unknown lsdtools error code {code!r}")
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint
        self.retryable = code == "temporary" if retryable is None else bool(retryable)
        self.data = data

    @property
    def status(self) -> int:
        return EXIT_STATUS[self.code]

    def to_json(self) -> dict:
        return {"code": self.code, "message": self.message, "hint": self.hint, "retryable": self.retryable}
