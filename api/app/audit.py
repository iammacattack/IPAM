"""Request audit (spec §11.1): one row for every request, reads included.

Rows are written on their own autocommit connection, so a request whose
transaction rolls back still leaves its audit record. Handlers enrich the row
through ``request.state.audit`` (action, object, site, changes).
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any
from urllib.parse import parse_qsl, urlencode

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .config import API_PREFIX
from .db import autocommit

log = logging.getLogger("ipam.audit")

EXCLUDED = {f"{API_PREFIX}/healthz", f"{API_PREFIX}/readyz", "/healthz", "/readyz", "/", "/favicon.ico"}
# Static UI files and the Swagger page carry no data; the API calls they make are audited.
EXCLUDED_PREFIXES = ("/ui/", "/docs")


def _excluded(path: str) -> bool:
    return path in EXCLUDED or path.startswith(EXCLUDED_PREFIXES)
REDACT = ("key", "token", "secret", "password")


def _redact_query(raw: str) -> str:
    pairs = [(k, "[REDACTED]" if any(r in k.lower() for r in REDACT) else v) for k, v in parse_qsl(raw, keep_blank_values=True)]
    return urlencode(pairs)


def write_event(event: dict[str, Any]) -> None:
    try:
        with autocommit() as conn:
            conn.execute(
                """
                INSERT INTO audit_event (request_id, actor_type, actor_id, actor_display, auth_method, mfa,
                    source_ip, user_agent, client_name, http_method, route, query, action, object_type,
                    object_key, site_code, outcome, status_code, error_code, duration_ms, changes)
                VALUES (%(requestId)s, %(actorType)s, %(actorId)s, %(actorDisplay)s, %(authMethod)s, %(mfa)s,
                    %(sourceIp)s, %(userAgent)s, %(clientName)s, %(httpMethod)s, %(route)s, %(query)s, %(action)s,
                    %(objectType)s, %(objectKey)s, %(siteCode)s, %(outcome)s, %(statusCode)s, %(errorCode)s,
                    %(durationMs)s, %(changes)s)
                """,
                {**_defaults(), **event, "changes": json.dumps(event["changes"]) if event.get("changes") else None},
            )
    except Exception:  # noqa: BLE001 - audit failure must be loud but mustn't crash the response
        log.exception("audit write failed for request %s", event.get("requestId"))


def _defaults() -> dict[str, Any]:
    keys = (
        "requestId actorType actorId actorDisplay authMethod mfa sourceIp userAgent clientName httpMethod route "
        "query action objectType objectKey siteCode outcome statusCode errorCode durationMs changes"
    ).split()
    return dict.fromkeys(keys)


def system_event(action: str, **fields: Any) -> None:
    write_event({"actorType": "system", "actorId": "system", "actorDisplay": "IPAM", "action": action, "outcome": "success", **fields})


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = uuid.uuid4()
        request.state.request_id = request_id
        request.state.audit = {}
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-Id"] = str(request_id)
            return response
        finally:
            if not _excluded(request.url.path):
                await run_in_threadpool(self._record, request, request_id, status, started)

    @staticmethod
    def _record(request: Request, request_id: uuid.UUID, status: int, started: float) -> None:
        a: dict[str, Any] = getattr(request.state, "audit", {}) or {}
        principal = getattr(request.state, "principal", None)
        route = request.scope.get("route")
        route_path = getattr(route, "path", None) or request.url.path
        write_event(
            {
                "requestId": str(request_id),
                "actorType": principal.actor_type if principal else "anonymous",
                "actorId": principal.actor_id if principal else a.get("actorId"),
                "actorDisplay": principal.display if principal else None,
                "authMethod": (principal.auth_method + (f" (step-up: {a['stepUp']})" if a.get("stepUp") else "")) if principal else None,
                "mfa": ("n/a" if principal.actor_type == "api-key" else str(principal.mfa).lower()) if principal else None,
                "sourceIp": request.client.host if request.client else None,
                "userAgent": request.headers.get("user-agent"),
                "clientName": request.headers.get("x-client-name") or "unknown",
                "httpMethod": request.method,
                "route": route_path,
                "query": _redact_query(request.url.query) if request.url.query else None,
                "action": a.get("action") or f"{request.method.lower()} {route_path}",
                "objectType": a.get("objectType"),
                "objectKey": a.get("objectKey"),
                "siteCode": a.get("siteCode"),
                "outcome": "success" if status < 400 else ("denied" if status in (401, 403) else "failure"),
                "statusCode": status,
                "errorCode": a.get("errorCode"),
                "durationMs": int((time.perf_counter() - started) * 1000),
                "changes": a.get("changes"),
            }
        )


def note(request: Request, action: str, **fields: Any) -> None:
    """Called by handlers to name what the request did."""
    request.state.audit.update({"action": action, **fields})
