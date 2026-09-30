"""Sites: reserve, confirm, extend, release, read (spec §8.2 "Sites", Workflow 2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .. import repo
from ..audit import note, system_event
from ..auth import Principal, require
from ..config import LIVE_SITE_STATUSES
from ..db import tx
from ..services import sites as ssvc

router = APIRouter(tags=["sites"])


class SiteIn(BaseModel):
    # Swagger pre-fills the request box from this example, so it must be a request that works as-is.
    model_config = ConfigDict(
        json_schema_extra={"examples": [{"siteCode": "DEMO1", "countryCode": "AU", "templateKey": "EXAMPLE-NET-10"}]}
    )

    siteCode: str = Field(description="Site code, used as supplied (e.g. X9). Must not be held by a live site.")
    countryCode: str | None = Field(None, description="ISO 3166-1 alpha-2, e.g. AU")
    templateKey: str = Field(description="A template with a RELEASED version, e.g. EXAMPLE-NET-10")
    templateVersion: int | None = Field(None, ge=1, description="Leave out to use the RELEASED version")
    baseIp: str | None = Field(None, description="Leave out to let the pool pick the next free block, e.g. 10.9.0.0")
    blocks: dict[str, str] | None = Field(None, description="Multi-block templates only: {blockKey: cidr}")
    pool: str | None = Field(None, description="Leave out to use the template's default pool")
    reservationDays: int | None = Field(None, ge=1, description="Leave out for the default (14 days)")
    externalRef: str | None = Field(None, description="Optional change or ticket reference")

    @field_validator("countryCode", "baseIp", "pool", "externalRef", mode="before")
    @classmethod
    def _blank_is_absent(cls, v: Any) -> Any:
        return None if isinstance(v, str) and not v.strip() else v


class ConfirmIn(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={"examples": [{"reservationId": "paste the reservationId from the POST /sites response"}]}
    )

    reservationId: str | None = Field(None, description="From the reservation block of the POST /sites response")
    changeRef: str | None = None


class ExtendIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"days": 14}]})

    days: int = Field(ge=1)


def _emit_expired(codes: list[str]) -> None:
    for code in codes:
        system_event("site.reservation_expired", objectType="site", objectKey=code, siteCode=code)


@router.post("/sites", status_code=201)
def reserve_site(
    request: Request,
    response: Response,
    body: SiteIn,
    dryRun: bool = False,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    principal: Principal = Depends(require("sites:deploy")),
):
    """Step 1 of 2 (FR-08): reserve. Allocates the block and holds every subnet, gateway and
    fixed host-pool member as `reserved` until `:confirm`, `:release` or expiry."""
    code = body.siteCode.strip().upper()
    note(request, "site.dry_run" if dryRun else "site.reserve", objectType="site", objectKey=code, siteCode=code)
    with tx() as conn:
        result, created, expired = ssvc.deploy(
            conn, body.model_dump(), principal.actor_id, request.headers.get("x-client-name"), idempotency_key, dryRun
        )
    _emit_expired(expired)
    if dryRun:
        response.status_code = 200
    elif not created:
        response.status_code = 200
        response.headers["Idempotent-Replay"] = "true"
        request.state.audit["action"] = "site.reserve_replay"
    else:
        request.state.audit["changes"] = {"after": {"status": "reserved", "blocks": result["blocks"]}}
    return result


@router.post("/sites/{site_code}:confirm")
def confirm_site(request: Request, site_code: str, body: ConfirmIn, principal: Principal = Depends(require("sites:deploy"))):
    """Step 2 of 2 (FR-08): reserved -> allocated. The expiry is removed and the space is permanent."""
    code = site_code.upper()
    note(request, "site.confirm", objectType="site", objectKey=code, siteCode=code)
    with tx() as conn:
        site = ssvc.confirm(conn, code, body.reservationId, principal.actor_id)
        out = ssvc.summary(conn, site)
    request.state.audit["changes"] = {"status": {"from": "reserved", "to": "allocated"}, "changeRef": body.changeRef}
    return out


@router.post("/sites/{site_code}:extend")
def extend_site(request: Request, site_code: str, body: ExtendIn, principal: Principal = Depends(require("sites:deploy"))):
    code = site_code.upper()
    note(request, "site.extend", objectType="site", objectKey=code, siteCode=code)
    with tx() as conn:
        site = ssvc.extend(conn, code, body.days, principal.actor_id)
        return ssvc.summary(conn, site)


@router.post("/sites/{site_code}:release")
def release_site(request: Request, site_code: str, principal: Principal = Depends(require("sites:deploy"))):
    """Cancel a reservation. The space returns to the pool at once."""
    code = site_code.upper()
    note(request, "site.release", objectType="site", objectKey=code, siteCode=code)
    with tx() as conn:
        site = ssvc.release(conn, code, principal.actor_id)
        return ssvc.summary(conn, site)


@router.get("/sites")
def list_sites(
    request: Request,
    status: str | None = None,
    expiringWithinDays: int | None = None,
    _: Principal = Depends(require("read")),
):
    note(request, "site.list")
    with tx() as conn:
        _emit_expired(ssvc.expire_due(conn))
        sql, params = "SELECT * FROM site WHERE true", []
        if status:
            sql += " AND status = ANY(%s)"
            params.append([s.strip() for s in status.split(",")])
        else:
            sql += " AND status = ANY(%s)"
            params.append(list(LIVE_SITE_STATUSES))
        if expiringWithinDays is not None:
            sql += " AND expires_at <= now() + make_interval(days => %s)"
            params.append(expiringWithinDays)
        rows = conn.execute(sql + " ORDER BY site_code, created_at", params).fetchall()
        return [ssvc.summary(conn, r) for r in rows]


@router.get("/sites/{site_code}")
def get_site(request: Request, site_code: str, _: Principal = Depends(require("read"))):
    code = site_code.upper()
    note(request, "site.read", objectType="site", objectKey=code, siteCode=code)
    with tx() as conn:
        _emit_expired(ssvc.expire_due(conn))
        return ssvc.summary(conn, repo.latest_site(conn, code))


@router.get("/sites/{site_code}/design")
def get_design(
    request: Request,
    site_code: str,
    section: str | None = None,
    vlanKey: str | None = None,
    include: str | None = Query("hosts", description="'hosts' to include host records, 'none' to omit"),
    _: Principal = Depends(require("read")),
):
    """FR-10: the whole site in one call."""
    code = site_code.upper()
    note(request, "design.read", objectType="site", objectKey=code, siteCode=code)
    with tx() as conn:
        _emit_expired(ssvc.expire_due(conn))
        site = repo.latest_site(conn, code)
        vk = repo.resolve_vlan_key(conn, vlanKey) if vlanKey else None
        return ssvc.design(conn, site, section=section, vlan_key=vk, include_hosts=(include or "") != "none")


@router.get("/sites/{site_code}/vlans/{vlan}")
def get_site_vlan(request: Request, site_code: str, vlan: str, _: Principal = Depends(require("read"))) -> dict[str, Any]:
    from ..services import lookups as lsvc

    code = site_code.upper()
    note(request, "lookup.vlan", objectType="site", objectKey=code, siteCode=code)
    with tx() as conn:
        _, attrs, _ = lsvc.vlan_lookup(conn, code, vlan)
    return attrs
