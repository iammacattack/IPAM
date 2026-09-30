"""Design data: VRFs, pools, VLAN library, host roles, templates (spec §8.2)."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from psycopg import errors as pg_errors

from ..audit import note
from ..auth import Principal, require
from ..db import tx
from ..errors import IpamError
from ..services import sites as ssvc
from ..services import templates as tsvc

router = APIRouter()
TEMPLATE_KEY = re.compile(r"^[A-Z0-9][A-Z0-9-]{1,63}$")


# --------------------------------------------------------------------------- #
# VRFs and pools
# --------------------------------------------------------------------------- #


@router.get("/vrfs", tags=["design"])
def list_vrfs(request: Request, _: Principal = Depends(require("read"))):
    note(request, "vrf.list")
    with tx() as conn:
        return [{"vrfKey": r["vrf_key"], "description": r["description"]} for r in conn.execute("SELECT * FROM vrf ORDER BY vrf_key")]


@router.get("/pools", tags=["design"])
def list_pools(request: Request, _: Principal = Depends(require("read"))):
    note(request, "pool.list")
    with tx() as conn:
        pools = conn.execute("SELECT * FROM pool ORDER BY pool_key").fetchall()
        prefixes = conn.execute("SELECT * FROM pool_prefix ORDER BY pool_key, position").fetchall()
        excl = conn.execute("SELECT * FROM pool_exclusion ORDER BY pool_key, cidr").fetchall()
        used = conn.execute("SELECT pool_key, count(*) AS n FROM block GROUP BY pool_key").fetchall()
    used_by = {u["pool_key"]: u["n"] for u in used}
    return [
        {
            "poolKey": p["pool_key"],
            "parentPool": p["parent_key"],
            "vrf": p["vrf_key"],
            "allocationPrefixLength": p["allocation_prefix_length"],
            "strategy": p["strategy"],
            "uniqueness": p["uniqueness"],
            "prefixes": [str(x["cidr"]) for x in prefixes if x["pool_key"] == p["pool_key"]],
            "exclusions": [str(x["cidr"]) for x in excl if x["pool_key"] == p["pool_key"]],
            "blocksAllocated": used_by.get(p["pool_key"], 0),
            "description": p["description"],
        }
        for p in pools
    ]


@router.get("/pools/{pool_key}/next-free", tags=["design"])
def pool_next_free(request: Request, pool_key: str, prefixLength: int | None = None, _: Principal = Depends(require("read"))):
    """Non-binding: the block a deploy would get now. Use POST /sites to hold it."""
    note(request, "pool.next_free", objectType="pool", objectKey=pool_key)
    with tx() as conn:
        return {"poolKey": pool_key, "cidr": str(ssvc.next_free(conn, pool_key, prefixLength)), "nonBinding": True}


# --------------------------------------------------------------------------- #
# VLAN library
# --------------------------------------------------------------------------- #


def _vlan_view(v: dict[str, Any], aliases: list[str]) -> dict[str, Any]:
    return {
        "vlanKey": v["vlan_key"],
        "vlanId": v["vlan_id"],
        "vlanName": v["vlan_name"],
        "aliases": aliases,
        "class": v["class"],
        "securityZone": v["security_zone"],
        "description": v["description"],
        "status": v["status"],
    }


@router.get("/vlans", tags=["design"])
def list_vlans(request: Request, vlanClass: str | None = Query(None, alias="class"), _: Principal = Depends(require("read"))):
    note(request, "vlan.list")
    with tx() as conn:
        sql, params = "SELECT * FROM vlan", []
        if vlanClass:
            sql, params = sql + " WHERE class = %s", [vlanClass]
        rows = conn.execute(sql + " ORDER BY vlan_key", params).fetchall()
        aliases = conn.execute("SELECT * FROM vlan_alias ORDER BY alias").fetchall()
    by_key: dict[str, list[str]] = {}
    for a in aliases:
        by_key.setdefault(a["vlan_key"], []).append(a["alias"])
    return [_vlan_view(r, by_key.get(r["vlan_key"], [])) for r in rows]


@router.get("/vlans/{vlan}", tags=["design"])
def get_vlan(request: Request, vlan: str, _: Principal = Depends(require("read"))):
    """Accepts a VLAN key or an alias."""
    with tx() as conn:
        from .. import repo

        key = repo.resolve_vlan_key(conn, vlan)
        row = conn.execute("SELECT * FROM vlan WHERE vlan_key = %s", (key,)).fetchone()
        aliases = [a["alias"] for a in conn.execute("SELECT alias FROM vlan_alias WHERE vlan_key = %s ORDER BY alias", (key,))]
    note(request, "vlan.read", objectType="vlan", objectKey=key)
    return _vlan_view(row, aliases)


class VlanIn(BaseModel):
    vlanKey: str = Field(pattern=r"^[A-Z0-9][A-Z0-9_-]*$")
    vlanId: int | None = Field(None, ge=2, le=4094)
    vlanName: str
    aliases: list[str] = []
    vlanClass: str | None = Field(None, alias="class")
    securityZone: str | None = None
    description: str | None = None


@router.post("/vlans", status_code=201, tags=["design"])
def create_vlan(request: Request, body: VlanIn, principal: Principal = Depends(require("templates:write"))):
    note(request, "vlan.create", objectType="vlan", objectKey=body.vlanKey, changes={"after": body.model_dump(by_alias=True)})
    try:
        with tx() as conn:
            row = conn.execute(
                """INSERT INTO vlan (vlan_key, vlan_id, vlan_name, class, security_zone, description)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING *""",
                (body.vlanKey, body.vlanId, body.vlanName, body.vlanClass, body.securityZone, body.description),
            ).fetchone()
            for a in body.aliases:
                conn.execute("INSERT INTO vlan_alias (alias, vlan_key) VALUES (%s, %s)", (a, body.vlanKey))
    except pg_errors.UniqueViolation as exc:
        raise IpamError("IPAM-VLAN-DUPLICATE", "VLAN key or name already exists", vlanKey=body.vlanKey) from exc
    except pg_errors.CheckViolation as exc:
        raise IpamError("IPAM-VLAN-ID-INVALID", str(exc.diag.message_primary)) from exc
    return _vlan_view(row, body.aliases)


# --------------------------------------------------------------------------- #
# Host roles (host type pools)
# --------------------------------------------------------------------------- #


@router.get("/host-roles", tags=["design"])
def list_host_roles(request: Request, _: Principal = Depends(require("read"))):
    note(request, "host_role.list")
    with tx() as conn:
        roles = conn.execute("SELECT * FROM host_role ORDER BY role_code").fetchall()
        members = conn.execute("SELECT * FROM host_role_member ORDER BY role_code, ordinal").fetchall()
    return [
        {
            "roleCode": r["role_code"],
            "name": r["name"],
            "vlanKeys": list(r["vlan_keys"]),
            "offsetMode": r["offset_mode"],
            "hostnamePattern": r["hostname_pattern"],
            "members": [
                {k2: m[k1] for k1, k2 in (("name", "name"), ("kind", "kind"), ("host_position", "hostPosition"),
                 ("secondary_host_octet", "secondaryHostOctet"), ("range_start", "rangeStart"), ("range_end", "rangeEnd"))
                 if m[k1] is not None}
                for m in members
                if m["role_code"] == r["role_code"]
            ],
        }
        for r in roles
    ]


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #


class TemplateIn(BaseModel):
    templateKey: str
    description: str | None = None
    content: dict[str, Any]


class VersionIn(BaseModel):
    content: dict[str, Any] | None = None
    fromVersion: int | None = None


class ContentIn(BaseModel):
    content: dict[str, Any]


class ReleaseIn(BaseModel):
    releaseNotes: str | None = None
    evidence: str | None = None


@router.get("/templates", tags=["templates"])
def list_templates(request: Request, state: str | None = None, _: Principal = Depends(require("read"))):
    """`?state=RELEASED` is what delivery tools use: only released versions are offered."""
    note(request, "template.list")
    states = [s.strip().upper() for s in state.split(",")] if state else None
    with tx() as conn:
        templates = conn.execute("SELECT * FROM template ORDER BY template_key").fetchall()
        versions = conn.execute("SELECT * FROM template_version ORDER BY template_key, version").fetchall()
        counts = {t["template_key"]: tsvc.site_counts(conn, t["template_key"]) for t in templates}
    out = []
    for t in templates:
        vs = [
            tsvc.version_view(v, include_content=False, sites=counts[t["template_key"]].get(v["version"], 0))
            for v in versions
            if v["template_key"] == t["template_key"] and (states is None or v["state"] in states)
        ]
        if states is None or vs:
            out.append({"templateKey": t["template_key"], "description": t["description"], "versions": vs})
    return out


@router.post("/templates", status_code=201, tags=["templates"])
def create_template(request: Request, body: TemplateIn, principal: Principal = Depends(require("templates:write"))):
    key = body.templateKey.strip().upper()
    if not TEMPLATE_KEY.match(key):
        raise IpamError("IPAM-TEMPLATE-INVALID", "templateKey must be UPPER-KEBAB, e.g. CAT-100")
    note(request, "template.create", objectType="template", objectKey=key)
    with tx() as conn:
        if conn.execute("SELECT 1 FROM template WHERE template_key = %s", (key,)).fetchone():
            raise IpamError("IPAM-TEMPLATE-EXISTS", f"Template {key} exists; add a version instead", templateKey=key)
        conn.execute(
            "INSERT INTO template (template_key, description, created_by) VALUES (%s, %s, %s)",
            (key, body.description, principal.actor_id),
        )
        row, created = tsvc.create_version(conn, key, body.content, principal.actor_id)
    return {**tsvc.version_view(row), "vlansCreated": created}


@router.get("/templates/{key}", tags=["templates"])
def get_template(request: Request, key: str, _: Principal = Depends(require("read"))):
    note(request, "template.read", objectType="template", objectKey=key.upper())
    with tx() as conn:
        t = conn.execute("SELECT * FROM template WHERE template_key = %s", (key.upper(),)).fetchone()
        if not t:
            raise IpamError("IPAM-TEMPLATE-NOT-FOUND", f"No template {key}")
        versions = conn.execute("SELECT * FROM template_version WHERE template_key = %s ORDER BY version", (t["template_key"],)).fetchall()
        counts = tsvc.site_counts(conn, t["template_key"])
    return {
        "templateKey": t["template_key"],
        "description": t["description"],
        "versions": [tsvc.version_view(v, include_content=False, sites=counts.get(v["version"], 0)) for v in versions],
    }


@router.post("/templates/{key}/versions", status_code=201, tags=["templates"])
def new_version(request: Request, key: str, body: VersionIn, principal: Principal = Depends(require("templates:write"))):
    """New DRAFT: given content, or a copy of fromVersion (default: the latest)."""
    key = key.upper()
    note(request, "template.version_create", objectType="template", objectKey=key)
    with tx() as conn:
        content = body.content
        if content is None:
            src = conn.execute(
                "SELECT content FROM template_version WHERE template_key = %s AND (%s::int IS NULL OR version = %s) ORDER BY version DESC LIMIT 1",
                (key, body.fromVersion, body.fromVersion),
            ).fetchone()
            if not src:
                raise IpamError("IPAM-TEMPLATE-NOT-FOUND", f"No template {key}")
            content = src["content"]
        elif not conn.execute("SELECT 1 FROM template WHERE template_key = %s", (key,)).fetchone():
            raise IpamError("IPAM-TEMPLATE-NOT-FOUND", f"No template {key}")
        row, created = tsvc.create_version(conn, key, content, principal.actor_id)
    return {**tsvc.version_view(row), "vlansCreated": created}


@router.get("/templates/{key}/versions/{version:int}", tags=["templates"])
def get_version(request: Request, key: str, version: int, _: Principal = Depends(require("read"))):
    note(request, "template.read", objectType="template", objectKey=f"{key.upper()}@v{version}")
    with tx() as conn:
        row = tsvc.get_version(conn, key.upper(), version)
        sites = tsvc.site_counts(conn, key.upper()).get(version, 0)
    return tsvc.version_view(row, sites=sites)


@router.patch("/templates/{key}/versions/{version:int}", tags=["templates"])
def patch_version(request: Request, key: str, version: int, body: ContentIn, _: Principal = Depends(require("templates:write"))):
    note(request, "template.update", objectType="template", objectKey=f"{key.upper()}@v{version}")
    with tx() as conn:
        row, created = tsvc.update_draft(conn, key.upper(), version, body.content)
    return {**tsvc.version_view(row), "vlansCreated": created}


@router.post("/templates/{key}/versions/{version:int}:validate", tags=["templates"])
def validate_version(request: Request, key: str, version: int, _: Principal = Depends(require("read"))):
    note(request, "template.validate", objectType="template", objectKey=f"{key.upper()}@v{version}")
    with tx() as conn:
        row = tsvc.get_version(conn, key.upper(), version)
        return {"ref": f"{row['template_key']}@v{row['version']}", "state": row["state"], **tsvc.validation_report(conn, row["content"])}


@router.post("/templates/{key}/versions/{version:int}:release", tags=["templates"])
def release_version(request: Request, key: str, version: int, body: ReleaseIn, principal: Principal = Depends(require("templates:write"))):
    note(request, "template.release", objectType="template", objectKey=f"{key.upper()}@v{version}")
    with tx() as conn:
        row = tsvc.release(conn, key.upper(), version, body.releaseNotes, body.evidence, principal.actor_id)
    request.state.audit["changes"] = {"state": {"to": "RELEASED"}, "contentHash": row["content_hash"]}
    return tsvc.version_view(row, include_content=False)


@router.get("/templates/{key}/versions/{version:int}/placement", tags=["templates"])
def version_placement(request: Request, key: str, version: int, _: Principal = Depends(require("read"))):
    """Host placement matrix: every fixed member x every VLAN it lives on, relative to the block."""
    from nextdc_ipam_engine import layout_from_content, placement_matrix

    from .. import repo

    note(request, "template.placement", objectType="template", objectKey=f"{key.upper()}@v{version}")
    with tx() as conn:
        row = tsvc.get_version(conn, key.upper(), version)
        cfg = repo.settings(conn)
        matrix = placement_matrix(
            layout_from_content(row["content"]),
            repo.host_pools(conn),
            avoid_zero_and_broadcast_in_supernets=bool(cfg["avoidZeroAndBroadcastOctetsInSupernets"]),
        )
    return {"ref": f"{row['template_key']}@v{row['version']}", "placements": [p.to_dict() for p in matrix]}


@router.get("/templates/{key}/preview", tags=["templates"])
def preview(
    request: Request,
    key: str,
    baseIp: str | None = None,
    version: int | None = None,
    pool: str | None = None,
    _: Principal = Depends(require("read")),
):
    """FR-06: the full computed design for any base IP. Nothing is persisted.

    Without baseIp the block shown is the one the pool would pick right now (non-binding).
    """
    note(request, "template.preview", objectType="template", objectKey=key.upper())
    with tx() as conn:
        return ssvc.preview(conn, key.upper(), version, baseIp, pool)
