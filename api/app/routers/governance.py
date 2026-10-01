"""Governance: audit log, site-code registry, health (spec §8.2 "Governance")."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request

from ..audit import note
from ..auth import Principal, require
from ..db import autocommit, tx

router = APIRouter()

AUDIT_COLUMNS = {
    "action": "action",
    "siteCode": "site_code",
    "actorId": "actor_id",
    "clientName": "client_name",
    "outcome": "outcome",
    "errorCode": "error_code",
    "objectKey": "object_key",
    "requestId": "request_id",
}


@router.get("/audit", tags=["governance"])
def audit(
    request: Request,
    action: str | None = None,
    siteCode: str | None = None,
    actorId: str | None = None,
    clientName: str | None = None,
    outcome: str | None = None,
    errorCode: str | None = None,
    objectKey: str | None = None,
    requestId: str | None = None,
    q: str | None = Query(None, description="Keyword across route, query, object and actor"),
    since: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
    _: Principal = Depends(require("audit.read")),
):
    """Search the audit log by its main columns or a keyword; newest first."""
    note(request, "audit.read")
    filters = {"action": action, "siteCode": siteCode, "actorId": actorId, "clientName": clientName, "outcome": outcome,
               "errorCode": errorCode, "objectKey": objectKey, "requestId": requestId}
    sql, params = "SELECT * FROM audit_event WHERE true", []
    for name, value in filters.items():
        if value is not None:
            sql += f" AND {AUDIT_COLUMNS[name]}::text = %s"
            params.append(value)
    if q:
        sql += " AND concat_ws(' ', route, query, object_key, actor_id, actor_display, client_name, action) ILIKE %s"
        params.append(f"%{q}%")
    if since:
        sql += " AND occurred_at >= %s"
        params.append(since)
    sql += " ORDER BY occurred_at DESC LIMIT %s"
    params.append(limit)
    with tx() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [
        {
            "eventId": str(r["event_id"]),
            "requestId": str(r["request_id"]) if r["request_id"] else None,
            "occurredAt": r["occurred_at"],
            "actorType": r["actor_type"],
            "actorId": r["actor_id"],
            "actorDisplay": r["actor_display"],
            "authMethod": r["auth_method"],
            "mfa": r["mfa"],
            "sourceIp": str(r["source_ip"]) if r["source_ip"] else None,
            "userAgent": r["user_agent"],
            "clientName": r["client_name"],
            "httpMethod": r["http_method"],
            "route": r["route"],
            "query": r["query"],
            "action": r["action"],
            "objectType": r["object_type"],
            "objectKey": r["object_key"],
            "siteCode": r["site_code"],
            "outcome": r["outcome"],
            "statusCode": r["status_code"],
            "errorCode": r["error_code"],
            "durationMs": r["duration_ms"],
            "changes": r["changes"],
        }
        for r in rows
    ]


@router.get("/site-codes", tags=["governance"])
def site_codes(request: Request, status: str | None = None, _: Principal = Depends(require("read"))):
    """Site-code registry. Codes supplied by clients are auto-registered as `unverified` for admin review."""
    note(request, "site_code.list")
    with tx() as conn:
        sql, params = "SELECT * FROM site_code", []
        if status:
            sql, params = sql + " WHERE status = %s", [status]
        rows = conn.execute(sql + " ORDER BY code", params).fetchall()
    return [
        {"code": r["code"], "countryCode": r["country_code"], "status": r["status"], "nonStandard": r["non_standard"],
         "firstSeenAt": r["first_seen_at"], "firstSeenBy": r["first_seen_by"]}
        for r in rows
    ]


@router.get("/healthz", tags=["health"], include_in_schema=False)
def healthz():
    return {"status": "ok"}


@router.get("/readyz", tags=["health"], include_in_schema=False)
def readyz():
    with autocommit() as conn:
        conn.execute("SELECT 1")
    return {"status": "ready"}
