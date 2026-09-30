"""Template versions: save, validate, release (spec §5.5, §5.5.1, §7).

POC lifecycle is DRAFT -> RELEASED. Releasing a new version moves the previous
RELEASED one to DEPRECATED (sites still use it) or RETIRED (none do), in the
same transaction, so there's never a moment with two released versions.
"""

from __future__ import annotations

from typing import Any

from psycopg.types.json import Jsonb

from nextdc_ipam_engine import (
    EngineError,
    EngineValidationError,
    Layout,
    content_hash,
    expand_vlan_rules,
    layout_from_content,
    placement_matrix,
)

from .. import repo
from ..config import LIVE_SITE_STATUSES
from ..errors import IpamError


# --------------------------------------------------------------------------- #
# Content preparation
# --------------------------------------------------------------------------- #


def ensure_vlans(conn, defs: list[dict[str, Any]]) -> int:
    """Create VLAN library entries a bulk rule needs (FR-07c). Returns how many were created."""
    created = 0
    for d in defs:
        existing = conn.execute("SELECT * FROM vlan WHERE vlan_key = %s", (d["vlanKey"],)).fetchone()
        if existing:
            if existing["vlan_id"] != d["vlanId"] or existing["vlan_name"] != d["vlanName"]:
                raise IpamError(
                    "IPAM-VLAN-DUPLICATE",
                    f"VLAN {d['vlanKey']} already exists as {existing['vlan_id']}/{existing['vlan_name']}",
                    vlanKey=d["vlanKey"],
                )
            continue
        clash = conn.execute("SELECT vlan_key FROM vlan WHERE vlan_name = %s", (d["vlanName"],)).fetchone()
        if clash:
            raise IpamError(
                "IPAM-VLAN-DUPLICATE",
                f"VLAN name {d['vlanName']} is already used by {clash['vlan_key']}",
                vlanName=d["vlanName"],
            )
        conn.execute(
            """INSERT INTO vlan (vlan_key, vlan_id, vlan_name, class, security_zone, description)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (d["vlanKey"], d["vlanId"], d["vlanName"], d.get("class"), d.get("securityZone"), d.get("description")),
        )
        created += 1
    return created


def prepare_content(conn, content: dict[str, Any]) -> tuple[dict[str, Any], Layout, int]:
    """Lay out, expand bulk VLAN rules into explicit bindings, and re-lay out."""
    layout = layout_from_content(content)
    expanded, defs = expand_vlan_rules(content, layout)
    created = ensure_vlans(conn, defs)
    return expanded, layout_from_content(expanded), created


# --------------------------------------------------------------------------- #
# Validation (release gate)
# --------------------------------------------------------------------------- #


def validation_report(conn, content: dict[str, Any]) -> dict[str, Any]:
    try:
        layout = layout_from_content(content)
    except EngineValidationError as err:
        return {"valid": False, "errors": [e.to_dict() for e in err.errors], "warnings": [], "summary": None}
    except EngineError as err:
        return {"valid": False, "errors": [err.to_dict()], "warnings": [], "summary": None}

    errors: list[dict[str, Any]] = []
    warnings: list[str] = []
    bound = [s for s in layout.subnets if s.vlan_key]
    library = repo.vlans(conn, [s.vlan_key for s in bound])
    seen_ids: dict[int, str] = {}
    for s in bound:
        v = library.get(s.vlan_key)
        if v is None:
            errors.append({"code": "IPAM-VLAN-UNKNOWN", "message": f"{s.vlan_key} isn't in the VLAN library", "vlanKey": s.vlan_key})
            continue
        if v["status"] != "active":
            errors.append({"code": "IPAM-VLAN-DEPRECATED", "message": f"{s.vlan_key} is deprecated", "vlanKey": s.vlan_key})
        if v["vlan_id"] is not None:
            if v["vlan_id"] in seen_ids:
                errors.append(
                    {
                        "code": "IPAM-VLAN-DUPLICATE",
                        "message": f"VLAN ID {v['vlan_id']} is used by both {seen_ids[v['vlan_id']]} and {s.vlan_key}",
                        "vlanId": v["vlan_id"],
                    }
                )
            else:
                seen_ids[v["vlan_id"]] = s.vlan_key
        if not v["security_zone"]:
            warnings.append(f"{s.vlan_key} has no security zone (STD-NET-SEGMENTATION REQ-01)")

    matrix = placement_matrix(
        layout,
        repo.host_pools(conn),
        avoid_zero_and_broadcast_in_supernets=bool(repo.settings(conn)["avoidZeroAndBroadcastOctetsInSupernets"]),
    )
    conflicts = [p.to_dict() for p in matrix if p.conflict]
    for c in conflicts:
        errors.append({**c["conflict"], "member": c["member"], "vlanKey": c["vlanKey"]})
    placed_warnings = [p.to_dict() for p in matrix if p.warnings and not p.conflict]

    unbound = len(layout.subnets) - len(bound)
    if unbound:
        warnings.append(f"{unbound} subnet(s) have no VLAN binding and will be reserved, unassigned")

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "summary": layout.summary(),
        "placement": {
            "members": len(matrix),
            "conflicts": len(conflicts),
            "highlighted": [
                {k: p[k] for k in ("roleCode", "member", "vlanKey", "subnet", "ip", "octetUsed", "warnings")}
                for p in placed_warnings
            ],
        },
    }


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #


def get_version(conn, key: str, version: int, *, for_update: bool = False) -> dict[str, Any]:
    sql = "SELECT * FROM template_version WHERE template_key = %s AND version = %s"
    row = conn.execute(sql + (" FOR UPDATE" if for_update else ""), (key, version)).fetchone()
    if row is None:
        raise IpamError("IPAM-TEMPLATE-NOT-FOUND", f"No template {key}@v{version}", templateKey=key, version=version)
    return row


def site_counts(conn, key: str) -> dict[int, int]:
    rows = conn.execute(
        """SELECT template_version, count(*) AS n FROM site
           WHERE template_key = %s AND status = ANY(%s) GROUP BY template_version""",
        (key, list(LIVE_SITE_STATUSES)),
    ).fetchall()
    return {r["template_version"]: r["n"] for r in rows}


def version_view(row: dict[str, Any], *, include_content: bool = True, sites: int | None = None) -> dict[str, Any]:
    out = {
        "templateKey": row["template_key"],
        "version": row["version"],
        "ref": f"{row['template_key']}@v{row['version']}",
        "state": row["state"],
        "contentHash": row["content_hash"],
        "summary": row["summary"],
        "createdAt": row["created_at"],
        "createdBy": row["created_by"],
        "releasedAt": row["released_at"],
        "releasedBy": row["released_by"],
        "releaseNotes": row["release_notes"],
        "evidence": row["evidence"],
    }
    if sites is not None:
        out["siteCount"] = sites
    if include_content:
        out["content"] = row["content"]
    return out


def released_version(conn, key: str, pinned: int | None = None) -> dict[str, Any]:
    if not conn.execute("SELECT 1 FROM template WHERE template_key = %s", (key,)).fetchone():
        raise IpamError("IPAM-TEMPLATE-NOT-FOUND", f"No template {key}", templateKey=key)
    if pinned is not None:
        row = get_version(conn, key, pinned)
        if row["state"] != "RELEASED":
            raise IpamError(
                "IPAM-TEMPLATE-NOT-RELEASED",
                f"{key}@v{pinned} is {row['state']}; only the RELEASED version can be deployed",
                templateKey=key,
                version=pinned,
                state=row["state"],
            )
        return row
    row = conn.execute(
        "SELECT * FROM template_version WHERE template_key = %s AND state = 'RELEASED'", (key,)
    ).fetchone()
    if row is None:
        raise IpamError("IPAM-TEMPLATE-NO-RELEASE", f"{key} has no RELEASED version", templateKey=key)
    return row


# --------------------------------------------------------------------------- #
# Writes
# --------------------------------------------------------------------------- #


def create_version(conn, key: str, content: dict[str, Any], actor: str) -> tuple[dict[str, Any], int]:
    expanded, layout, created = prepare_content(conn, content)
    nxt = conn.execute(
        "SELECT coalesce(max(version), 0) + 1 AS v FROM template_version WHERE template_key = %s", (key,)
    ).fetchone()["v"]
    row = conn.execute(
        """INSERT INTO template_version (template_key, version, state, content, content_hash, summary, created_by)
           VALUES (%s, %s, 'DRAFT', %s, %s, %s, %s) RETURNING *""",
        (key, nxt, Jsonb(expanded), content_hash(expanded), Jsonb(layout.summary()), actor),
    ).fetchone()
    return row, created


def update_draft(conn, key: str, version: int, content: dict[str, Any]) -> tuple[dict[str, Any], int]:
    row = get_version(conn, key, version, for_update=True)
    if row["state"] != "DRAFT":
        raise IpamError(
            "IPAM-TEMPLATE-FROZEN",
            f"{key}@v{version} is {row['state']}; create a new version to change it",
            templateKey=key,
            version=version,
        )
    expanded, layout, created = prepare_content(conn, content)
    row = conn.execute(
        """UPDATE template_version SET content = %s, content_hash = %s, summary = %s
           WHERE template_key = %s AND version = %s RETURNING *""",
        (Jsonb(expanded), content_hash(expanded), Jsonb(layout.summary()), key, version),
    ).fetchone()
    return row, created


def release(conn, key: str, version: int, notes: str | None, evidence: str | None, actor: str) -> dict[str, Any]:
    # Serialise releases per template key.
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"template:{key}",))
    row = get_version(conn, key, version, for_update=True)
    if row["state"] not in ("DRAFT", "TESTING"):
        raise IpamError("IPAM-TEMPLATE-FROZEN", f"{key}@v{version} is already {row['state']}", state=row["state"])
    if not (notes or "").strip() or not (evidence or "").strip():
        raise IpamError("IPAM-RELEASE-NOTES-REQUIRED", "Release needs releaseNotes and evidence", status=422)
    if repo.settings(conn)["twoPersonRelease"] and row["created_by"] == actor:
        raise IpamError("IPAM-RELEASE-SAME-AUTHOR", "The author can't release their own version", status=403)
    report = validation_report(conn, row["content"])
    if not report["valid"]:
        raise IpamError("IPAM-RELEASE-BLOCKED", f"{key}@v{version} fails release validation", report=report)

    prev = conn.execute(
        "SELECT version FROM template_version WHERE template_key = %s AND state = 'RELEASED' FOR UPDATE", (key,)
    ).fetchone()
    if prev:
        in_use = site_counts(conn, key).get(prev["version"], 0)
        conn.execute(
            "UPDATE template_version SET state = %s WHERE template_key = %s AND version = %s",
            ("DEPRECATED" if in_use else "RETIRED", key, prev["version"]),
        )
    return conn.execute(
        """UPDATE template_version
           SET state = 'RELEASED', released_at = now(), released_by = %s, release_notes = %s, evidence = %s
           WHERE template_key = %s AND version = %s RETURNING *""",
        (actor, notes, evidence, key, version),
    ).fetchone()
