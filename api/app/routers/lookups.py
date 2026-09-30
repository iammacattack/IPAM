"""Script-friendly lookups (spec §8.2 lookups, §8.2.1). `Accept: text/plain` returns the bare value."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from ..audit import note
from ..auth import Principal, require
from ..db import tx
from ..errors import IpamError
from ..services import lookups as lsvc

router = APIRouter(tags=["lookups"])


def wants_text(request: Request) -> bool:
    return "text/plain" in (request.headers.get("accept") or "")


def _plain(value: Any) -> PlainTextResponse:
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, dict):  # validateOctet
        value = "true" if value.get("usable") else "false"
    return PlainTextResponse(str(value))


@router.get("/lookup/host-ip")
def lookup_host_ip(
    request: Request,
    site: str,
    vlan: str | None = None,
    host: str | None = None,
    role: str | None = None,
    instance: int | None = None,
    resolve: str | None = None,
    hostname: str | None = None,
    principal: Principal = Depends(require("read")),
):
    """Host IP by site + VLAN (key or alias) + host-pool member (Workflow 3), or by role + instance.

    `resolve=assign&hostname=` claims the reserved address for that machine (needs `hosts:write`).
    """
    code = site.upper()
    assigning = resolve == "assign"
    if resolve not in (None, "assign"):
        raise IpamError("IPAM-BAD-REQUEST", "resolve must be 'assign' if given")
    if assigning and "hosts:write" not in principal.scopes:
        raise IpamError("IPAM-SCOPE-MISSING", "resolve=assign needs the 'hosts:write' scope")
    note(request, "host.assign" if assigning else "lookup.host", objectType="host", objectKey=host or role, siteCode=code)
    with tx() as conn:
        site_row, rec = lsvc.find_host(conn, code, vlan=vlan, host=host, role=role, instance=instance, for_update=assigning)
        before = rec["status"]
        if assigning:
            rec = lsvc.assign(conn, site_row, rec, hostname, principal.actor_id)
        view = lsvc.host_view(site_row, rec)
    request.state.audit["objectKey"] = f"{view['member']}@{view['vlanKey']}"
    if assigning and before != view["status"]:
        request.state.audit["changes"] = {"status": {"from": before, "to": view["status"]}, "hostname": view["hostname"], "ip": view["ip"]}
    return _plain(view["ip"]) if wants_text(request) else view


@router.get("/lookup/vlan")
def lookup_vlan(
    request: Request,
    site: str,
    vlan: str,
    field: str | None = None,
    index: int | None = None,
    octet: int | None = None,
    _: Principal = Depends(require("read")),
):
    """FR-10a: one attribute of the VLAN's subnet at the site, or all of them as JSON."""
    code = site.upper()
    note(request, "lookup.vlan", objectType="vlan", objectKey=vlan, siteCode=code)
    with tx() as conn:
        _, attrs, value = lsvc.vlan_lookup(conn, code, vlan, field, index, octet)
    request.state.audit["objectKey"] = f"{attrs['vlanKey']}{'.' + field if field else ''}"
    if field is None:
        return attrs
    if wants_text(request):
        return _plain(value)
    return {"siteCode": attrs["siteCode"], "siteStatus": attrs["siteStatus"], "vlanKey": attrs["vlanKey"], "field": field, "value": value}


@router.get("/lookup/network")
def lookup_network(request: Request, site: str, vlan: str, part: str | None = None, _: Principal = Depends(require("read"))):
    """Shorthand: cidr, or `part=network` for the network portion (3OCT)."""
    field = "networkPortion" if part == "network" else "cidr"
    code = site.upper()
    note(request, "lookup.vlan", objectType="vlan", objectKey=vlan, siteCode=code)
    with tx() as conn:
        _, attrs, value = lsvc.vlan_lookup(conn, code, vlan, field)
    return _plain(value) if wants_text(request) else {"siteCode": code, "vlanKey": attrs["vlanKey"], "field": field, "value": value}


class Token(BaseModel):
    vlan: str
    host: str | None = None
    field: str | None = None
    index: int | None = None
    octet: int | None = None


class TokensIn(BaseModel):
    site: str
    tokens: list[Token]


@router.post("/lookup:resolve-tokens")
def resolve_tokens(request: Request, body: TokensIn, _: Principal = Depends(require("read"))):
    """Batch form for IaC: one result per token, errors reported per token."""
    code = body.site.upper()
    note(request, "lookup.batch", objectType="site", objectKey=code, siteCode=code)
    with tx() as conn:
        results = lsvc.resolve_tokens(conn, code, [t.model_dump(exclude_none=True) for t in body.tokens])
    failed = sum(1 for r in results if "error" in r)
    request.state.audit["changes"] = {"tokens": len(results), "failed": failed}
    return {"site": code, "resolved": len(results) - failed, "failed": failed, "results": results}
