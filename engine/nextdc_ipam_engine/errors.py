"""Engine error type.

Every failure carries a stable ``IPAM-*`` code (spec §7) so the API can map it
straight onto an RFC 9457 problem response without re-interpreting messages.
"""

from __future__ import annotations

from typing import Any


class EngineError(Exception):
    def __init__(self, code: str, message: str, **detail: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, **self.detail}


class EngineValidationError(EngineError):
    """Several errors found in one pass (template validation reports them all)."""

    def __init__(self, errors: list[EngineError]) -> None:
        first = errors[0]
        super().__init__(
            first.code,
            f"{len(errors)} validation error(s); first: {first.message}",
            errors=[e.to_dict() for e in errors],
        )
        self.errors = errors
