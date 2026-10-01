"""Library MACD: VLANs, host pools, address pools and VRFs (spec §5.2-5.6, §7, §8.2).

Every change is audited with before/after. Deletes are refused while anything still uses the
item (templates, live sites, other pools); the error lists exactly what, so it can be cleared
first - or, for VLANs, deprecated instead. Configuration changes never move addresses already
materialised at sites (spec §5.6).
"""

from __future__ import annotations

import re
from ipaddress import ip_network
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from psycopg import errors as pg_errors

from nextdc_ipam_engine import EngineError, HostPool, HostPosition, layout_from_content, placement_matrix

from .. import repo
from ..audit import note
from ..auth import Principal, require
from ..config import LIVE_SITE_STATUSES
from ..db import tx
from ..errors import IpamError
from .design import _vlan_view

router = APIRouter(tags=["library"])

LIVE = list(LIVE_SITE_STATUSES)
KEY_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{0,63}$")
PRIVATE = [ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]
ZONES = ("Internal", "DataCentre", "DMZ", "OOB", "Perimeter")


def _key(raw: str, what: str) -> str:
    key = raw.strip().upper()
    if not KEY_RE.match(key):
        raise IpamError("IPAM-KEY-INVALID-FORMAT", f"{what} keys are UPPER-KEBAB: A-Z, 0-9, '-' or '_' (e.g. DCS-SERVERS)")
    return key


def _cidr(raw: str):
    try:
        return ip_network(raw.strip(), strict=True)
    except ValueError as exc:
        try:
            loose = ip_network(raw.strip(), strict=False)
            raise IpamError("IPAM-CIDR-INVALID", f"{raw} has host bits set; did you mean {loose}?", suggested=str(loose)) from exc
        except ValueError:
            raise IpamError("IPAM-CIDR-INVALID", f"'{raw}' isn't a CIDR like 10.0.0.0/8") from exc


def _templates_using(conn, path: str, key: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        f"""SELECT template_key, version, state FROM template_version
            WHERE jsonb_path_exists(content, '{path}', jsonb_build_object('k', %s::text))
            ORDER BY template_key, version""",
        (key,),
    ).fetchall()
    return [{"template": f"{r['template_key']}@v{r['version']}", "state": r["state"]} for r in rows]


def _released_conflicts(conn) -> list[dict[str, Any]]:
    """Host placement problems in RELEASED templates under the current host pools (run inside the change's transaction)."""
    cfg = repo.settings(conn)
    pools = repo.host_pools(conn)
    problems = []
    for v in conn.execute("SELECT template_key, version, content FROM template_version WHERE state = 'RELEASED'").fetchall():
        try:
            matrix = placement_matrix(layout_from_content(v["content"]), pools,
                                      avoid_zero_and_broadcast_in_supernets=bool(cfg["avoidZeroAndBroadcastOctetsInSupernets"]))
        except EngineError:
            continue
        for p in matrix:
            if p.conflict:
                problems.append({"template": f"{v['template_key']}@v{v['version']}", "member": p.member, "vlanKey": p.vlan_key,
                                 "message": p.conflict.get("message")})
    return problems


# =========================================================================== VLANs


class VlanPatch(BaseModel):
    model_config = ConfigDict(populate_by_name=True, json_schema_extra={"examples": [{"description": "Updated description", "aliases": ["SERVERS"]}]})
    vlanId: int | None = Field(None, ge=2, le=4094)
    vlanName: str | None = None
    aliases: list[str] | None = None
    vlanClass: str | None = Field(None, alias="class")
    securityZone: str | None = None
    description: str | None = None
    status: str | None = Field(None, pattern="^(active|deprecated)$")
    clearVlanId: bool = Field(False, description="Set the VLAN ID to none (untagged/OOB)")


def vlan_usage(conn, key: str) -> dict[str, Any]:
    templates = _templates_using(conn, "$.blocks[*].sections[*].vlanBindings[*] ? (@.vlanKey == $k)", key)
    sites = conn.execute(
        """SELECT DISTINCT s.site_code, s.status FROM subnet n JOIN site s USING (site_id)
           WHERE n.vlan_key = %s AND s.status = ANY(%s) ORDER BY s.site_code""",
        (key, LIVE),
    ).fetchall()
    pools = [r["role_code"] for r in conn.execute("SELECT role_code FROM host_role WHERE %s = ANY(vlan_keys) ORDER BY role_code", (key,))]
    return {"templates": templates, "sites": [dict(r) for r in sites], "hostPools": pools,
            "inUse": bool(templates or sites or pools)}


def _vlan_row(conn, key: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM vlan WHERE vlan_key = %s", (key.upper(),)).fetchone()
    if row is None:
        raise IpamError("IPAM-VLAN-UNKNOWN", f"No VLAN {key}", status=404)
    return row


def _aliases(conn, key: str) -> list[str]:
    return [a["alias"] for a in conn.execute("SELECT alias FROM vlan_alias WHERE vlan_key = %s ORDER BY alias", (key,))]


@router.get("/vlans/{key}/usage")
def get_vlan_usage(request: Request, key: str, _: Principal = Depends(require("read"))):
    """Where a VLAN is used: template versions, live sites, host pools."""
    note(request, "vlan.usage", objectType="vlan", objectKey=key.upper())
    with tx() as conn:
        _vlan_row(conn, key)
        return vlan_usage(conn, key.upper())


@router.patch("/vlans/{key}")
def update_vlan(request: Request, key: str, body: VlanPatch, _: Principal = Depends(require("vlans.write"))):
    """Change a VLAN. The key never changes. The VLAN ID can't change while a live site carries it
    (sites keep the ID they were deployed with), nor clash with another VLAN in a template that uses it."""
    key = key.upper()
    note(request, "vlan.update", objectType="vlan", objectKey=key)
    if body.securityZone == "":
        body.securityZone = None
    if body.securityZone and body.securityZone not in ZONES:
        raise IpamError("IPAM-ZONE-INVALID", f"Security zone must be one of {', '.join(ZONES)}")
    with tx() as conn:
        before = _vlan_row(conn, key)
        new_id = None if body.clearVlanId else (body.vlanId if body.vlanId is not None else before["vlan_id"])
        if new_id != before["vlan_id"]:
            live = vlan_usage(conn, key)["sites"]
            if live:
                raise IpamError("IPAM-VLAN-IN-USE", f"{key} is carried by {len(live)} live site(s) with ID {before['vlan_id']}; "
                                "create a new VLAN instead of renumbering this one", status=409, sites=[s["site_code"] for s in live])
            if new_id is not None:
                for t in _templates_using(conn, "$.blocks[*].sections[*].vlanBindings[*] ? (@.vlanKey == $k)", key):
                    tk, tv = t["template"].split("@v")
                    content = conn.execute("SELECT content FROM template_version WHERE template_key = %s AND version = %s", (tk, int(tv))).fetchone()["content"]
                    keys = [b["vlanKey"] for blk in content["blocks"] for s in blk["sections"] for b in s.get("vlanBindings", []) if b["vlanKey"] != key]
                    clash = conn.execute("SELECT vlan_key FROM vlan WHERE vlan_key = ANY(%s) AND vlan_id = %s", (keys, new_id)).fetchone()
                    if clash:
                        raise IpamError("IPAM-VLAN-DUPLICATE", f"ID {new_id} is already used by {clash['vlan_key']} in {t['template']}", status=409)
        try:
            row = conn.execute(
                """UPDATE vlan SET vlan_id = %s, vlan_name = coalesce(%s, vlan_name), class = coalesce(%s, class),
                       security_zone = coalesce(%s, security_zone), description = coalesce(%s, description), status = coalesce(%s, status)
                   WHERE vlan_key = %s RETURNING *""",
                (new_id, body.vlanName, body.vlanClass, body.securityZone, body.description, body.status, key),
            ).fetchone()
        except pg_errors.UniqueViolation as exc:
            raise IpamError("IPAM-VLAN-DUPLICATE", f"VLAN name {body.vlanName} is already used", status=409) from exc
        if body.aliases is not None:
            conn.execute("DELETE FROM vlan_alias WHERE vlan_key = %s", (key,))
            for a in sorted({a.strip() for a in body.aliases if a.strip()}):
                conn.execute("INSERT INTO vlan_alias (alias, vlan_key) VALUES (%s, %s)", (a, key))
        after = _vlan_view(row, _aliases(conn, key))
    request.state.audit["changes"] = {"before": _vlan_view(before, []) | {"aliases": None}, "after": after}
    return after


@router.delete("/vlans/{key}")
def delete_vlan(request: Request, key: str, _: Principal = Depends(require("vlans.write"))):
    """Delete an unused VLAN. If anything uses it, the answer lists what; deprecate it instead."""
    key = key.upper()
    note(request, "vlan.delete", objectType="vlan", objectKey=key)
    with tx() as conn:
        before = _vlan_row(conn, key)
        usage = vlan_usage(conn, key)
        if usage["inUse"]:
            raise IpamError("IPAM-VLAN-IN-USE", f"{key} is still used, so it can't be deleted. Deprecate it instead, or remove it from what uses it first.",
                            status=409, usage=usage)
        conn.execute("DELETE FROM vlan WHERE vlan_key = %s", (key,))
    request.state.audit["changes"] = {"before": _vlan_view(before, [])}
    return {"deleted": key}


# =========================================================================== host pools


class MemberIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    kind: str = Field("fixed", pattern="^(fixed|range|reserved)$")
    hostPosition: str | None = Field(None, description="fixed members: index.octet, e.g. 61 or 1.10")
    secondaryHostOctet: int | None = Field(None, ge=0, le=255)
    rangeStart: int | None = Field(None, ge=0, le=255)
    rangeEnd: int | None = Field(None, ge=0, le=255)


class HostRoleIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "roleCode": "JMP", "name": "Jump hosts", "vlanKeys": ["CORP-SERVERS"], "offsetMode": "literalOctet",
        "members": [{"name": "JMP01", "kind": "fixed", "hostPosition": "0.71"}, {"name": "JMP02", "kind": "fixed", "hostPosition": "0.72"}]}]})
    roleCode: str
    name: str | None = None
    vlanKeys: list[str] = Field(default_factory=list)
    hostnamePattern: str | None = None
    offsetMode: str = Field("literalOctet", pattern="^(literalOctet|fromNetwork)$")
    members: list[MemberIn] = Field(default_factory=list)


class HostRolePatch(BaseModel):
    name: str | None = None
    vlanKeys: list[str] | None = None
    hostnamePattern: str | None = None
    offsetMode: str | None = Field(None, pattern="^(literalOctet|fromNetwork)$")


def _check_members(members: list[MemberIn]) -> None:
    seen = set()
    for m in members:
        n = m.name.strip().upper()
        if n in seen:
            raise IpamError("IPAM-MEMBER-DUPLICATE", f"Member {n} appears twice")
        seen.add(n)
        if m.kind == "fixed":
            if not m.hostPosition:
                raise IpamError("IPAM-HOST-POSITION-INVALID", f"{n}: a fixed member needs a host position (e.g. 61 or 1.10)")
            HostPosition.parse(m.hostPosition)
        else:
            if m.rangeStart is None or m.rangeEnd is None or m.rangeStart > m.rangeEnd:
                raise IpamError("IPAM-RANGE-INVALID", f"{n}: a {m.kind} member needs a start and end octet, start <= end")


def _check_vlans(conn, keys: list[str]) -> list[str]:
    keys = sorted({k.strip().upper() for k in keys if k.strip()})
    known = {r["vlan_key"] for r in conn.execute("SELECT vlan_key FROM vlan WHERE vlan_key = ANY(%s)", (keys,))}
    missing = [k for k in keys if k not in known]
    if missing:
        raise IpamError("IPAM-VLAN-UNKNOWN", f"Unknown VLAN key(s): {', '.join(missing)}", status=404, vlanKeys=missing)
    return keys


def _pool_collisions(conn) -> list[str]:
    """Spec §7: no two host-pool members sharing a VLAN may use the same position, or a fixed member sit in another's range."""
    pools = repo.host_pools(conn)
    by_vlan: dict[str, list[tuple[str, Any]]] = {}
    for p in pools:
        for v in p.vlan_keys:
            for m in p.members:
                by_vlan.setdefault(v, []).append((p.role_code, m))
    problems = []
    for vlan, entries in by_vlan.items():
        fixed = [(r, m) for r, m in entries if m.kind == "fixed" and m.position]
        ranges = [(r, m) for r, m in entries if m.kind != "fixed" and m.range_start is not None]
        seen: dict[tuple[int, int], str] = {}
        for r, m in fixed:
            k = (m.position.index, m.position.octet)
            if k in seen:
                problems.append(f"{seen[k]} and {r}/{m.name} both use position {m.position} on {vlan}")
            else:
                seen[k] = f"{r}/{m.name}"
            for r2, m2 in ranges:
                if m.position.index == 0 and m2.range_start <= m.position.octet <= m2.range_end:
                    problems.append(f"{r}/{m.name} (.{m.position.octet}) falls inside {r2}/{m2.name} (.{m2.range_start}-.{m2.range_end}) on {vlan}")
        for i, (r, m) in enumerate(ranges):
            for r2, m2 in ranges[i + 1:]:
                if m.range_start <= m2.range_end and m2.range_start <= m.range_end:
                    problems.append(f"{r}/{m.name} and {r2}/{m2.name} ranges overlap on {vlan}")
    return problems


def _validate_pools(conn) -> None:
    clashes = _pool_collisions(conn)
    if clashes:
        raise IpamError("IPAM-HOST-COLLISION", "Host pools sharing a VLAN would collide", status=409, collisions=clashes)
    broken = _released_conflicts(conn)
    if broken:
        raise IpamError("IPAM-RELEASED-TEMPLATE-CONFLICT",
                        "This change would leave released template(s) with host-placement conflicts, so new sites couldn't be deployed from them",
                        status=409, conflicts=broken)


def _role_view(conn, code: str) -> dict[str, Any]:
    r = conn.execute("SELECT * FROM host_role WHERE role_code = %s", (code,)).fetchone()
    if r is None:
        raise IpamError("IPAM-ROLE-UNKNOWN", f"No host pool {code}", status=404)
    members = conn.execute("SELECT * FROM host_role_member WHERE role_code = %s ORDER BY ordinal", (code,)).fetchall()
    in_use = conn.execute(
        """SELECT count(*) AS n FROM ip_record i JOIN site s USING (site_id) WHERE i.role_code = %s AND s.status = ANY(%s)""",
        (code, LIVE),
    ).fetchone()["n"]
    return {
        "roleCode": r["role_code"], "name": r["name"], "vlanKeys": list(r["vlan_keys"]), "hostnamePattern": r["hostname_pattern"],
        "offsetMode": r["offset_mode"], "addressesAtSites": in_use,
        "members": [{k2: m[k1] for k1, k2 in (("name", "name"), ("kind", "kind"), ("host_position", "hostPosition"),
                     ("secondary_host_octet", "secondaryHostOctet"), ("range_start", "rangeStart"), ("range_end", "rangeEnd"))} for m in members],
    }


def _write_members(conn, code: str, members: list[MemberIn]) -> None:
    conn.execute("DELETE FROM host_role_member WHERE role_code = %s", (code,))
    for i, m in enumerate(members):
        conn.execute(
            """INSERT INTO host_role_member (role_code, name, ordinal, kind, host_position, secondary_host_octet, range_start, range_end)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (code, m.name.strip().upper(), i, m.kind, str(HostPosition.parse(m.hostPosition)) if m.kind == "fixed" else None,
             m.secondaryHostOctet if m.kind == "fixed" else None,
             m.rangeStart if m.kind != "fixed" else None, m.rangeEnd if m.kind != "fixed" else None),
        )


@router.post("/host-roles", status_code=201)
def create_host_role(request: Request, body: HostRoleIn, _: Principal = Depends(require("hostroles.write"))):
    code = _key(body.roleCode, "Host pool")
    note(request, "hostrole.create", objectType="host-role", objectKey=code)
    _check_members(body.members)
    with tx() as conn:
        vlans = _check_vlans(conn, body.vlanKeys)
        try:
            with conn.transaction():
                conn.execute(
                    "INSERT INTO host_role (role_code, name, vlan_keys, hostname_pattern, offset_mode) VALUES (%s, %s, %s, %s, %s)",
                    (code, body.name, vlans, body.hostnamePattern, body.offsetMode),
                )
        except pg_errors.UniqueViolation as exc:
            raise IpamError("IPAM-ROLE-EXISTS", f"Host pool {code} already exists", status=409) from exc
        _write_members(conn, code, body.members)
        _validate_pools(conn)
        view = _role_view(conn, code)
    request.state.audit["changes"] = {"after": view}
    return view


@router.patch("/host-roles/{code}")
def update_host_role(request: Request, code: str, body: HostRolePatch, _: Principal = Depends(require("hostroles.write"))):
    code = code.upper()
    note(request, "hostrole.update", objectType="host-role", objectKey=code)
    with tx() as conn:
        before = _role_view(conn, code)
        vlans = _check_vlans(conn, body.vlanKeys) if body.vlanKeys is not None else None
        conn.execute(
            """UPDATE host_role SET name = coalesce(%s, name), vlan_keys = coalesce(%s, vlan_keys),
                   hostname_pattern = coalesce(%s, hostname_pattern), offset_mode = coalesce(%s, offset_mode) WHERE role_code = %s""",
            (body.name, vlans, body.hostnamePattern, body.offsetMode, code),
        )
        _validate_pools(conn)
        after = _role_view(conn, code)
    request.state.audit["changes"] = {"before": before, "after": after}
    return after


@router.put("/host-roles/{code}/members")
def replace_members(request: Request, code: str, members: list[MemberIn], _: Principal = Depends(require("hostroles.write"))):
    """Replace the pool's member list. Addresses already held at sites stay where they are (spec §5.6)."""
    code = code.upper()
    note(request, "hostrole.members_update", objectType="host-role", objectKey=code)
    _check_members(members)
    with tx() as conn:
        before = _role_view(conn, code)
        _write_members(conn, code, members)
        _validate_pools(conn)
        after = _role_view(conn, code)
    request.state.audit["changes"] = {"before": before["members"], "after": after["members"]}
    return after


@router.delete("/host-roles/{code}")
def delete_host_role(request: Request, code: str, _: Principal = Depends(require("hostroles.write"))):
    code = code.upper()
    note(request, "hostrole.delete", objectType="host-role", objectKey=code)
    with tx() as conn:
        before = _role_view(conn, code)
        if before["addressesAtSites"]:
            sites = [r["site_code"] for r in conn.execute(
                "SELECT DISTINCT s.site_code FROM ip_record i JOIN site s USING (site_id) WHERE i.role_code = %s AND s.status = ANY(%s) ORDER BY 1",
                (code, LIVE))]
            raise IpamError("IPAM-HOSTROLE-IN-USE", f"{code} has {before['addressesAtSites']} address(es) held at live sites, so it can't be deleted",
                            status=409, sites=sites)
        conn.execute("DELETE FROM host_role WHERE role_code = %s", (code,))
    request.state.audit["changes"] = {"before": before}
    return {"deleted": code}


# =========================================================================== VRFs


class VrfIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"vrfKey": "CSMS", "description": "CSMS routing domain"}]})
    vrfKey: str
    description: str | None = None


class VrfPatch(BaseModel):
    description: str | None = None


def vrf_usage(conn, key: str) -> dict[str, Any]:
    pools = [r["pool_key"] for r in conn.execute("SELECT pool_key FROM pool WHERE vrf_key = %s ORDER BY 1", (key,))]
    blocks = conn.execute("SELECT count(*) AS n FROM block WHERE vrf_key = %s", (key,)).fetchone()["n"]
    subnets = conn.execute("SELECT count(*) AS n FROM subnet WHERE vrf_key = %s", (key,)).fetchone()["n"]
    templates = _templates_using(conn, "$.blocks[*] ? (@.vrf == $k)", key) + _templates_using(conn, "$.blocks[*].sections[*] ? (@.vrf == $k)", key)
    return {"pools": pools, "blocks": blocks, "subnets": subnets, "templates": templates,
            "inUse": bool(pools or blocks or subnets or templates)}


@router.post("/vrfs", status_code=201)
def create_vrf(request: Request, body: VrfIn, _: Principal = Depends(require("pools.write"))):
    key = _key(body.vrfKey, "VRF")
    note(request, "vrf.create", objectType="vrf", objectKey=key, changes={"after": body.model_dump()})
    with tx() as conn:
        try:
            conn.execute("INSERT INTO vrf (vrf_key, description) VALUES (%s, %s)", (key, body.description))
        except pg_errors.UniqueViolation as exc:
            raise IpamError("IPAM-VRF-EXISTS", f"VRF {key} already exists", status=409) from exc
    return {"vrfKey": key, "description": body.description}


@router.patch("/vrfs/{key}")
def update_vrf(request: Request, key: str, body: VrfPatch, _: Principal = Depends(require("pools.write"))):
    key = key.upper()
    note(request, "vrf.update", objectType="vrf", objectKey=key)
    with tx() as conn:
        before = conn.execute("SELECT * FROM vrf WHERE vrf_key = %s", (key,)).fetchone()
        if before is None:
            raise IpamError("IPAM-NOT-FOUND", f"No VRF {key}", status=404)
        conn.execute("UPDATE vrf SET description = %s WHERE vrf_key = %s", (body.description, key))
    request.state.audit["changes"] = {"before": {"description": before["description"]}, "after": body.model_dump()}
    return {"vrfKey": key, "description": body.description}


@router.get("/vrfs/{key}/usage")
def get_vrf_usage(request: Request, key: str, _: Principal = Depends(require("read"))):
    note(request, "vrf.usage", objectType="vrf", objectKey=key.upper())
    with tx() as conn:
        return vrf_usage(conn, key.upper())


@router.delete("/vrfs/{key}")
def delete_vrf(request: Request, key: str, _: Principal = Depends(require("pools.write"))):
    key = key.upper()
    note(request, "vrf.delete", objectType="vrf", objectKey=key)
    with tx() as conn:
        if conn.execute("SELECT 1 FROM vrf WHERE vrf_key = %s", (key,)).fetchone() is None:
            raise IpamError("IPAM-NOT-FOUND", f"No VRF {key}", status=404)
        usage = vrf_usage(conn, key)
        if usage["inUse"]:
            raise IpamError("IPAM-VRF-IN-USE", f"{key} is still used, so it can't be deleted", status=409, usage=usage)
        conn.execute("DELETE FROM vrf WHERE vrf_key = %s", (key,))
    return {"deleted": key}


# =========================================================================== address pools


class PoolIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "poolKey": "SITE-POOL-NZ", "parentPool": "ENTERPRISE", "vrf": "NXT", "allocationPrefixLength": 16,
        "prefixes": ["10.0.0.0/8"], "exclusions": [], "description": "Site blocks for New Zealand"}]})
    poolKey: str
    parentPool: str | None = None
    vrf: str
    allocationPrefixLength: int | None = Field(None, ge=8, le=30)
    strategy: str = Field("first-fit", pattern="^(first-fit|sequential-from-last)$")
    uniqueness: str = Field("enterprise", pattern="^(enterprise|vrf)$")
    description: str | None = None
    prefixes: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    confirmNonPrivate: bool = Field(False, description="Required to add a prefix outside RFC 1918 / RFC 6598 (spec §5.3)")


class PoolPatch(BaseModel):
    description: str | None = None
    allocationPrefixLength: int | None = Field(None, ge=8, le=30)
    strategy: str | None = Field(None, pattern="^(first-fit|sequential-from-last)$")
    uniqueness: str | None = Field(None, pattern="^(enterprise|vrf)$")
    status: str | None = Field(None, pattern="^(active|disabled)$")


class CidrIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"cidr": "172.16.0.0/12"}]})
    cidr: str
    confirmNonPrivate: bool = False


def _pool(conn, key: str, *, lock: bool = False) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM pool WHERE pool_key = %s" + (" FOR UPDATE" if lock else ""), (key,)).fetchone()
    if row is None:
        raise IpamError("IPAM-POOL-UNKNOWN", f"No pool {key}", status=404)
    return row


def _pool_view(conn, key: str) -> dict[str, Any]:
    p = _pool(conn, key)
    return {
        "poolKey": p["pool_key"], "parentPool": p["parent_key"], "vrf": p["vrf_key"], "allocationPrefixLength": p["allocation_prefix_length"],
        "strategy": p["strategy"], "uniqueness": p["uniqueness"], "status": p["status"], "description": p["description"],
        "prefixes": [str(r["cidr"]) for r in conn.execute("SELECT cidr FROM pool_prefix WHERE pool_key = %s ORDER BY position", (key,))],
        "exclusions": [str(r["cidr"]) for r in conn.execute("SELECT cidr FROM pool_exclusion WHERE pool_key = %s ORDER BY cidr", (key,))],
        "blocksAllocated": conn.execute("SELECT count(*) AS n FROM block WHERE pool_key = %s", (key,)).fetchone()["n"],
    }


def _add_prefix(conn, key: str, raw: str, confirm: bool) -> str:
    net = _cidr(raw)
    if not any(net.subnet_of(p) for p in PRIVATE) and not confirm:
        raise IpamError("IPAM-PREFIX-NOT-PRIVATE", f"{net} isn't RFC 1918 or RFC 6598 private space. Public space belongs in the INTERNET/DMZ VRFs; "
                        "confirm explicitly if this is intended.", status=422, cidr=str(net), needsConfirmation=True)
    pool = _pool(conn, key)
    if pool["parent_key"]:
        parent = [ip_network(r["cidr"]) for r in conn.execute("SELECT cidr FROM pool_prefix WHERE pool_key = %s", (pool["parent_key"],))]
        if not any(net.subnet_of(p) for p in parent):
            raise IpamError("IPAM-PREFIX-OUTSIDE-PARENT", f"{net} isn't inside parent pool {pool['parent_key']} ({', '.join(map(str, parent)) or 'no prefixes'})",
                            status=422)
        # Allocation pools under one parent can't overlap each other (spec §5.3).
        for r in conn.execute(
            """SELECT p.pool_key, pp.cidr FROM pool p JOIN pool_prefix pp USING (pool_key)
               WHERE p.parent_key = %s AND p.pool_key <> %s""", (pool["parent_key"], key)
        ).fetchall():
            if net.overlaps(ip_network(r["cidr"])):
                raise IpamError("IPAM-POOL-OVERLAP", f"{net} overlaps {r['cidr']} in sibling pool {r['pool_key']}", status=409)
    if conn.execute("SELECT 1 FROM pool_prefix WHERE pool_key = %s AND cidr = %s", (key, str(net))).fetchone():
        raise IpamError("IPAM-PREFIX-EXISTS", f"{net} is already a prefix of {key}", status=409)
    pos = conn.execute("SELECT coalesce(max(position), -1) + 1 AS p FROM pool_prefix WHERE pool_key = %s", (key,)).fetchone()["p"]
    conn.execute("INSERT INTO pool_prefix (pool_key, cidr, position) VALUES (%s, %s, %s)", (key, str(net), pos))
    return str(net)


def _add_exclusion(conn, key: str, raw: str) -> str:
    net = _cidr(raw)
    taken = conn.execute(
        "SELECT b.cidr, s.site_code FROM block b JOIN site s USING (site_id) WHERE b.pool_key = %s AND b.cidr && %s::cidr LIMIT 1",
        (key, str(net)),
    ).fetchone()
    if taken:
        raise IpamError("IPAM-EXCLUSION-ALLOCATED", f"{net} overlaps {taken['cidr']}, already allocated to {taken['site_code']}", status=409)
    try:
        with conn.transaction():
            conn.execute("INSERT INTO pool_exclusion (pool_key, cidr) VALUES (%s, %s)", (key, str(net)))
    except pg_errors.UniqueViolation as exc:
        raise IpamError("IPAM-EXCLUSION-EXISTS", f"{net} is already excluded", status=409) from exc
    return str(net)


@router.post("/pools", status_code=201)
def create_pool(request: Request, body: PoolIn, _: Principal = Depends(require("pools.write"))):
    key = _key(body.poolKey, "Pool")
    note(request, "pool.create", objectType="pool", objectKey=key)
    with tx() as conn:
        if not conn.execute("SELECT 1 FROM vrf WHERE vrf_key = %s", (body.vrf.upper(),)).fetchone():
            raise IpamError("IPAM-NOT-FOUND", f"No VRF {body.vrf}", status=404)
        if body.parentPool:
            _pool(conn, body.parentPool.upper())
        try:
            with conn.transaction():
                conn.execute(
                    """INSERT INTO pool (pool_key, parent_key, vrf_key, allocation_prefix_length, strategy, uniqueness, description)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                    (key, body.parentPool.upper() if body.parentPool else None, body.vrf.upper(), body.allocationPrefixLength,
                     body.strategy, body.uniqueness, body.description),
                )
        except pg_errors.UniqueViolation as exc:
            raise IpamError("IPAM-POOL-EXISTS", f"Pool {key} already exists", status=409) from exc
        for c in body.prefixes:
            _add_prefix(conn, key, c, body.confirmNonPrivate)
        for c in body.exclusions:
            _add_exclusion(conn, key, c)
        view = _pool_view(conn, key)
    request.state.audit["changes"] = {"after": view}
    return view


@router.patch("/pools/{key}")
def update_pool(request: Request, key: str, body: PoolPatch, _: Principal = Depends(require("pools.write"))):
    key = key.upper()
    note(request, "pool.update", objectType="pool", objectKey=key)
    with tx() as conn:
        before = _pool_view(conn, key)
        if body.allocationPrefixLength is not None and body.allocationPrefixLength != before["allocationPrefixLength"] and before["blocksAllocated"]:
            raise IpamError("IPAM-POOL-IN-USE", f"{key} has {before['blocksAllocated']} block(s) allocated; its block size can't change", status=409)
        conn.execute(
            """UPDATE pool SET description = coalesce(%s, description), allocation_prefix_length = coalesce(%s, allocation_prefix_length),
                   strategy = coalesce(%s, strategy), uniqueness = coalesce(%s, uniqueness), status = coalesce(%s, status) WHERE pool_key = %s""",
            (body.description, body.allocationPrefixLength, body.strategy, body.uniqueness, body.status, key),
        )
        after = _pool_view(conn, key)
    request.state.audit["changes"] = {"before": before, "after": after}
    return after


@router.post("/pools/{key}/prefixes", status_code=201)
def add_pool_prefix(request: Request, key: str, body: CidrIn, _: Principal = Depends(require("pools.write"))):
    """Add a parent prefix, e.g. 172.16.0.0/12 to ENTERPRISE (spec §5.3)."""
    key = key.upper()
    note(request, "pool.prefix_add", objectType="pool", objectKey=key)
    with tx() as conn:
        added = _add_prefix(conn, key, body.cidr, body.confirmNonPrivate)
        view = _pool_view(conn, key)
    request.state.audit["changes"] = {"added": added}
    return view


@router.delete("/pools/{key}/prefixes")
def remove_pool_prefix(request: Request, key: str, cidr: str = Query(..., description="e.g. 172.16.0.0/12"), _: Principal = Depends(require("pools.write"))):
    """Remove a prefix - only if nothing has been allocated from it and no child pool draws on it."""
    key = key.upper()
    note(request, "pool.prefix_remove", objectType="pool", objectKey=key)
    net = _cidr(cidr)
    with tx() as conn:
        _pool(conn, key, lock=True)
        if not conn.execute("SELECT 1 FROM pool_prefix WHERE pool_key = %s AND cidr = %s", (key, str(net))).fetchone():
            raise IpamError("IPAM-NOT-FOUND", f"{net} isn't a prefix of {key}", status=404)
        used = conn.execute(
            "SELECT b.cidr, s.site_code FROM block b JOIN site s USING (site_id) WHERE b.pool_key = %s AND b.cidr <<= %s::cidr LIMIT 1",
            (key, str(net)),
        ).fetchone()
        if used:
            raise IpamError("IPAM-PREFIX-IN-USE", f"{net} has allocations (e.g. {used['cidr']} for {used['site_code']})", status=409)
        child = conn.execute(
            """SELECT p.pool_key FROM pool p JOIN pool_prefix pp USING (pool_key) WHERE p.parent_key = %s AND pp.cidr <<= %s::cidr LIMIT 1""",
            (key, str(net)),
        ).fetchone()
        if child:
            raise IpamError("IPAM-PREFIX-IN-USE", f"Child pool {child['pool_key']} draws on {net}", status=409)
        conn.execute("DELETE FROM pool_prefix WHERE pool_key = %s AND cidr = %s", (key, str(net)))
        view = _pool_view(conn, key)
    request.state.audit["changes"] = {"removed": str(net)}
    return view


@router.post("/pools/{key}/exclusions", status_code=201)
def add_pool_exclusion(request: Request, key: str, body: CidrIn, _: Principal = Depends(require("pools.write"))):
    """Space the pool must never hand out (e.g. a legacy /16)."""
    key = key.upper()
    note(request, "pool.exclusion_add", objectType="pool", objectKey=key)
    with tx() as conn:
        _pool(conn, key, lock=True)
        added = _add_exclusion(conn, key, body.cidr)
        view = _pool_view(conn, key)
    request.state.audit["changes"] = {"added": added}
    return view


@router.delete("/pools/{key}/exclusions")
def remove_pool_exclusion(request: Request, key: str, cidr: str = Query(...), _: Principal = Depends(require("pools.write"))):
    key = key.upper()
    note(request, "pool.exclusion_remove", objectType="pool", objectKey=key)
    net = _cidr(cidr)
    with tx() as conn:
        _pool(conn, key, lock=True)
        if conn.execute("DELETE FROM pool_exclusion WHERE pool_key = %s AND cidr = %s RETURNING 1", (key, str(net))).fetchone() is None:
            raise IpamError("IPAM-NOT-FOUND", f"{net} isn't an exclusion of {key}", status=404)
        view = _pool_view(conn, key)
    request.state.audit["changes"] = {"removed": str(net)}
    return view


@router.delete("/pools/{key}")
def delete_pool(request: Request, key: str, _: Principal = Depends(require("pools.write"))):
    key = key.upper()
    note(request, "pool.delete", objectType="pool", objectKey=key)
    with tx() as conn:
        before = _pool_view(conn, key)
        children = [r["pool_key"] for r in conn.execute("SELECT pool_key FROM pool WHERE parent_key = %s ORDER BY 1", (key,))]
        templates = _templates_using(conn, "$.blocks[*] ? (@.defaultPool == $k)", key)
        if before["blocksAllocated"] or children or templates:
            raise IpamError("IPAM-POOL-IN-USE", f"{key} is still used, so it can't be deleted", status=409,
                            usage={"blocksAllocated": before["blocksAllocated"], "childPools": children, "templates": templates})
        conn.execute("DELETE FROM pool WHERE pool_key = %s", (key,))
    request.state.audit["changes"] = {"before": before}
    return {"deleted": key}
