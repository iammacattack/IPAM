"""RFC 9457 problem responses with stable IPAM-* codes (spec §7)."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from nextdc_ipam_engine import EngineError

# HTTP status for codes that aren't validation failures (422 is the default).
STATUS_BY_CODE: dict[str, int] = {
    "IPAM-AUTH-REQUIRED": 401,
    "IPAM-KEY-INVALID": 401,
    "IPAM-KEY-EXPIRED": 401,
    "IPAM-KEY-REVOKED": 401,
    "IPAM-SCOPE-MISSING": 403,
    "IPAM-NOT-FOUND": 404,
    "IPAM-SITE-NOT-FOUND": 404,
    "IPAM-TEMPLATE-NOT-FOUND": 404,
    "IPAM-VLAN-UNKNOWN": 404,
    "IPAM-VLAN-NOT-AT-SITE": 404,
    "IPAM-HOST-NOT-ON-VLAN": 404,
    "IPAM-ROLE-UNKNOWN": 404,
    "IPAM-POOL-UNKNOWN": 404,
    "IPAM-FIELD-UNKNOWN": 400,
    "IPAM-VLAN-REQUIRED": 400,
    "IPAM-BAD-REQUEST": 400,
    "IPAM-OVERLAP": 409,
    "IPAM-SITE-CODE-IN-USE": 409,
    "IPAM-ALIAS-AMBIGUOUS": 409,
    "IPAM-POOL-EXHAUSTED": 409,
    "IPAM-HOST-ALREADY-ASSIGNED": 409,
    "IPAM-HOSTNAME-IN-USE": 409,
    "IPAM-HOST-OCTET-CONFLICT": 409,
    "IPAM-SITE-NOT-CONFIRMED": 409,
    "IPAM-SITE-STATE": 409,
    "IPAM-RESERVATION-MISMATCH": 409,
    "IPAM-RESERVATION-EXPIRED": 409,
    "IPAM-TEMPLATE-NO-RELEASE": 409,
    "IPAM-TEMPLATE-NOT-RELEASED": 409,
    "IPAM-TEMPLATE-FROZEN": 409,
    "IPAM-TEMPLATE-EXISTS": 409,
    "IPAM-VLAN-DUPLICATE": 409,
    "IPAM-RELEASE-BLOCKED": 409,
    "IPAM-IDEMPOTENCY-IN-PROGRESS": 409,
    "IPAM-INTERNAL": 500,
}


class IpamError(Exception):
    def __init__(self, code: str, message: str, status: int | None = None, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status or STATUS_BY_CODE.get(code, 422)
        self.extra = extra

    @classmethod
    def from_engine(cls, err: EngineError) -> "IpamError":
        return cls(err.code, err.message, **err.detail)


def problem(request: Request, status: int, code: str, message: str, extra: dict[str, Any] | None = None) -> JSONResponse:
    request.state.audit = getattr(request.state, "audit", {}) or {}
    request.state.audit["errorCode"] = code
    body = {
        "type": f"https://ipam.nextdc.internal/errors/{code}",
        "title": code,
        "status": status,
        "code": code,
        "detail": message,
        "requestId": str(getattr(request.state, "request_id", "")),
        **(extra or {}),
    }
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


async def ipam_error_handler(request: Request, exc: IpamError) -> JSONResponse:
    return problem(request, exc.status, exc.code, exc.message, exc.extra)


async def engine_error_handler(request: Request, exc: EngineError) -> JSONResponse:
    err = IpamError.from_engine(exc)
    return problem(request, err.status, err.code, err.message, err.extra)
