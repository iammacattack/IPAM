"""Site deploy: reserve, confirm, extend, release, expire (spec §5.7, §6.3, FR-08/08a/09).

Deploy always *reserves* first. Everything the template defines - block,
subnets, gateways, fixed host-pool members - is claimed in one transaction,
so none of it can be allocated elsewhere while the reservation stands.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Any

import psycopg
from psycopg import errors as pg_errors

from nextdc_ipam_engine import (
    EngineError,
    Layout,
    check_base,
    layout_from_content,
    place_members,
    relocate,
    vlan_attributes,
)

from .. import repo
from ..config import LIVE_SITE_STATUSES
from ..errors import IpamError
from . import templates as tsvc

SITE_CODE_CHARS = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,15}$")
# STD-INF-SITE-NAMING §3.1 as understood for the POC: 1-3 letters then 1-2 digits (B1, S4, PH1).
SITE_CODE_STANDARD = re.compile(r"^[A-Z]{1,3}[0-9]{1,2}$")


# --------------------------------------------------------------------------- #
# Pool allocation (spec §6.3)
# --------------------------------------------------------------------------- #


def next_free(conn, pool_key: str, prefix_length: int | None = None) -> IPv4Network:
    pool = conn.execute("SELECT * FROM pool WHERE pool_key = %s", (pool_key,)).fetchone()
    if pool is None:
        raise IpamError("IPAM-POOL-UNKNOWN", f"No pool '{pool_key}'", poolKey=pool_key)
    plen = prefix_length or pool["allocation_prefix_length"]
    if not plen:
        raise IpamError("IPAM-BAD-REQUEST", f"Pool {pool_key} has no allocation prefix length")
    prefixes = [ip_network(r["cidr"]) for r in conn.execute(
        "SELECT cidr FROM pool_prefix WHERE pool_key = %s ORDER BY position", (pool_key,)
    ).fetchall()]
    excluded = [ip_network(r["cidr"]) for r in conn.execute(
        "SELECT cidr FROM pool_exclusion WHERE pool_key = %s", (pool_key,)
    ).fetchall()]
    if pool["uniqueness"] == "enterprise":
        taken_rows = conn.execute("SELECT cidr FROM block").fetchall()
    else:
        taken_rows = conn.execute("SELECT cidr FROM block WHERE vrf_key = %s", (pool["vrf_key"],)).fetchall()
    blocked = excluded + [ip_network(r["cidr"]) for r in taken_rows]
    for prefix in prefixes:
        if plen < prefix.prefixlen:
            continue
        for candidate in prefix.subnets(new_prefix=plen):
            if not any(candidate.overlaps(b) for b in blocked):
                return candidate
    raise IpamError("IPAM-POOL-EXHAUSTED", f"No free /{plen} left in {pool_key}", poolKey=pool_key)


# --------------------------------------------------------------------------- #
# Materialisation (shared by preview, dry run and deploy)
# --------------------------------------------------------------------------- #


def materialise(conn, layout: Layout, bases: dict[str, IPv4Network]) -> list[dict[str, Any]]:
    """Apply a layout to real bases. Returns one dict per subnet, hosts included."""
    cfg = repo.settings(conn)
    library = repo.vlans(conn, [s.vlan_key for s in layout.subnets if s.vlan_key])
    networks: list[dict[str, Any]] = []
    by_vlan: dict[str, tuple[IPv4Network, IPv4Address]] = {}
    for block in layout.blocks:
        base = bases[block.key]
        for s in block.subnets:
            cidr = relocate(s.relative, base)
            gw = cidr.network_address + s.gateway_offset
            v = library.get(s.vlan_key) if s.vlan_key else None
            networks.append(
                {
                    "blockKey": block.key,
                    "section": s.section,
                    "vrf": s.vrf,
                    "relativeCidr": str(s.relative),
                    "_cidr": cidr,
                    "_gateway": gw,
                    "vlanKey": s.vlan_key,
                    "vlanId": v["vlan_id"] if v else None,
                    "vlanName": v["vlan_name"] if v else None,
                    "vlanClass": v["class"] if v else None,
                    "securityZone": v["security_zone"] if v else None,
                    "hosts": [],
                }
            )
            if s.vlan_key:
                by_vlan[s.vlan_key] = (cidr, gw)

    placements = place_members(
        by_vlan,
        repo.host_pools(conn),
        avoid_zero_and_broadcast_in_supernets=bool(cfg["avoidZeroAndBroadcastOctetsInSupernets"]),
    )
    conflicts = [p.to_dict() for p in placements if p.conflict]
    if conflicts:
        raise IpamError(
            "IPAM-HOST-OCTET-CONFLICT",
            f"{len(conflicts)} host-pool member(s) can't be placed at this site",
            conflicts=conflicts,
        )
    by_key = {n["vlanKey"]: n for n in networks if n["vlanKey"]}
    for p in placements:
        by_key[p.vlan_key]["hosts"].append(
            {
                "roleCode": p.role_code,
                "member": p.member,
                "hostPosition": p.host_position,
                "octetUsed": p.octet_used,
                "ip": str(p.ip),
                "hostname": None,
                "status": "reserved-pattern",
            }
        )
    return networks


def network_view(n: dict[str, Any], include_hosts: bool = True) -> dict[str, Any]:
    cidr: IPv4Network = n["_cidr"]
    attrs = vlan_attributes(cidr, n["_gateway"])
    out = {
        "section": n["section"],
        "vrf": n["vrf"],
        "vlanKey": n["vlanKey"],
        "vlanId": n["vlanId"],
        "vlanName": n["vlanName"],
        "vlanClass": n["vlanClass"],
        "securityZone": n["securityZone"],
        "relativeCidr": n["relativeCidr"],
        "cidr": attrs["cidr"],
        "network": attrs["network"],
        "prefix": attrs["prefix"],
        "mask": attrs["mask"],
        "gateway": attrs["gateway"],
        "broadcast": attrs["broadcast"],
        "firstUsable": attrs["firstUsable"],
        "lastUsable": attrs["lastUsable"],
        "networkPortion": attrs["networkPortion"],
    }
    if "status" in n:
        out["status"] = n["status"]
    if include_hosts:
        out["hosts"] = n["hosts"]
    return out


# --------------------------------------------------------------------------- #
# Deploy
# --------------------------------------------------------------------------- #


def _resolve_bases(conn, layout: Layout, body: dict[str, Any]) -> tuple[dict[str, IPv4Network], dict[str, str | None]]:
    bases: dict[str, IPv4Network] = {}
    pools: dict[str, str | None] = {}
    explicit: dict[str, str] = dict(body.get("blocks") or {})
    if body.get("baseIp"):
        if len(layout.blocks) != 1:
            raise IpamError("IPAM-BAD-REQUEST", "baseIp is only for single-block templates; use blocks: {KEY: cidr}")
        explicit.setdefault(layout.blocks[0].key, body["baseIp"])
    for block in layout.blocks:
        if block.key in explicit:
            bases[block.key] = check_base(str(explicit[block.key]), block.prefix_length)
            pools[block.key] = None
            continue
        pool_key = body.get("pool") or block.default_pool
        if not pool_key:
            raise IpamError("IPAM-BAD-REQUEST", f"Block {block.key} has no default pool; give a baseIp or pool")
        # Two concurrent deploys can't pick the same block (spec §6.3).
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"pool:{pool_key}",))
        bases[block.key] = next_free(conn, pool_key, block.prefix_length)
        pools[block.key] = pool_key
    return bases, pools


def _register_site_code(conn, code: str, country: str | None, actor: str) -> None:
    conn.execute(
        """INSERT INTO site_code (code, country_code, non_standard, first_seen_by)
           VALUES (%s, %s, %s, %s) ON CONFLICT (code) DO NOTHING""",
        (code, country, SITE_CODE_STANDARD.match(code) is None, actor),
    )


def _overlap_detail(conn, cidr: IPv4Network) -> dict[str, Any]:
    row = conn.execute(
        """SELECT b.cidr, s.site_code, s.status FROM block b JOIN site s USING (site_id)
           WHERE b.cidr && %s::cidr LIMIT 1""",
        (str(cidr),),
    ).fetchone()
    if not row:
        return {"requested": str(cidr)}
    return {"requested": str(cidr), "conflictsWith": str(row["cidr"]), "heldBySite": row["site_code"], "siteStatus": row["status"]}


def deploy(
    conn, body: dict[str, Any], actor: str, client_name: str | None, idem_key: str | None, dry_run: bool
) -> tuple[dict[str, Any], bool, list[str]]:
    """Returns (site design, created, site codes expired on the way).

    created=False means a dry run or an idempotent replay of an earlier request.
    """
    code = str(body.get("siteCode") or "").strip().upper()
    if not SITE_CODE_CHARS.match(code):
        raise IpamError("IPAM-SITE-CODE-INVALID", f"'{body.get('siteCode')}' isn't a usable site code (A-Z, 0-9, '-')")

    if idem_key and not dry_run:
        prior = conn.execute("SELECT * FROM site WHERE idempotency_key = %s", (idem_key,)).fetchone()
        if prior:
            return design(conn, prior), False, []

    expired = expire_due(conn)

    tpl = tsvc.released_version(conn, str(body.get("templateKey") or ""), body.get("templateVersion"))
    layout = layout_from_content(tpl["content"])
    cfg = repo.settings(conn)
    days = int(body.get("reservationDays") or cfg["siteReservationDays"])
    if not (1 <= days <= int(cfg["siteReservationMaxDays"])):
        raise IpamError("IPAM-BAD-REQUEST", f"reservationDays must be 1-{cfg['siteReservationMaxDays']}")

    live = conn.execute(
        "SELECT site_code, status FROM site WHERE site_code = %s AND status = ANY(%s)", (code, list(LIVE_SITE_STATUSES))
    ).fetchone()
    if live:
        raise IpamError("IPAM-SITE-CODE-IN-USE", f"Site code {code} is held by a live site ({live['status']})", siteCode=code)

    bases, pools = _resolve_bases(conn, layout, body)
    networks = materialise(conn, layout, bases)

    if dry_run:
        return {
            "dryRun": True,
            "siteCode": code,
            "template": _template_ref(tpl),
            "blocks": [{"blockKey": k, "cidr": str(v), "pool": pools[k]} for k, v in bases.items()],
            "subnetCount": len(networks),
            "networks": [network_view(n) for n in networks],
        }, False, expired

    _register_site_code(conn, code, body.get("countryCode"), actor)
    reservation_id = uuid.uuid4()
    try:
        site = conn.execute(
            """INSERT INTO site (site_code, country_code, status, template_key, template_version, template_content_hash,
                                 reservation_id, expires_at, reserved_by, client_name, idempotency_key, external_ref)
               VALUES (%s, %s, 'reserved', %s, %s, %s, %s, now() + make_interval(days => %s), %s, %s, %s, %s)
               RETURNING *""",
            (code, body.get("countryCode"), tpl["template_key"], tpl["version"], tpl["content_hash"], reservation_id,
             days, actor, client_name, idem_key, body.get("externalRef")),
        ).fetchone()
    except pg_errors.UniqueViolation as exc:
        name = exc.diag.constraint_name
        if name == "site_code_live":
            raise IpamError("IPAM-SITE-CODE-IN-USE", f"Site code {code} is held by a live site", siteCode=code) from exc
        raise IpamError("IPAM-IDEMPOTENCY-IN-PROGRESS", "A request with this Idempotency-Key is already being processed") from exc

    block_ids: dict[str, uuid.UUID] = {}
    by_key = {b.key: b for b in layout.blocks}
    for key, cidr in bases.items():
        try:
            with conn.transaction():
                row = conn.execute(
                    "INSERT INTO block (site_id, block_key, vrf_key, pool_key, cidr) VALUES (%s, %s, %s, %s, %s) RETURNING block_id",
                    (site["site_id"], key, by_key[key].vrf, pools[key], str(cidr)),
                ).fetchone()
        except pg_errors.ExclusionViolation as exc:
            raise IpamError("IPAM-OVERLAP", f"{cidr} overlaps an existing allocation", **_overlap_detail(conn, cidr)) from exc
        block_ids[key] = row["block_id"]

    _insert_networks(conn, site["site_id"], block_ids, networks)
    return design(conn, site), True, expired


def _insert_networks(conn, site_id, block_ids: dict[str, uuid.UUID], networks: list[dict[str, Any]]) -> None:
    subnet_rows, ip_rows = [], []
    for n in networks:
        sid = uuid.uuid4()
        subnet_rows.append(
            (sid, site_id, block_ids[n["blockKey"]], n["section"], n["vrf"], str(n["_cidr"]), n["relativeCidr"],
             n["vlanKey"], n["vlanId"], str(n["_gateway"]))
        )
        ip_rows.append((site_id, sid, n["vrf"], str(n["_gateway"]), "gateway", None, None, None, None))
        for h in n["hosts"]:
            ip_rows.append((site_id, sid, n["vrf"], h["ip"], "reserved-pattern", h["roleCode"], h["member"], h["hostPosition"], h["octetUsed"]))
    with conn.cursor() as cur:
        try:
            cur.executemany(
                """INSERT INTO subnet (subnet_id, site_id, block_id, section, vrf_key, cidr, relative_cidr, vlan_key, vlan_id, gateway)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                subnet_rows,
            )
        except pg_errors.ExclusionViolation as exc:
            raise IpamError("IPAM-OVERLAP", "A subnet overlaps an existing allocation in the same VRF", detail=str(exc.diag.message_detail)) from exc
        cur.executemany(
            """INSERT INTO ip_record (site_id, subnet_id, vrf_key, ip, status, role_code, member_name, host_position, octet_used)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            ip_rows,
        )


def _template_ref(tpl: dict[str, Any]) -> dict[str, Any]:
    return {"key": tpl["template_key"], "version": tpl["version"], "state": tpl["state"], "contentHash": tpl["content_hash"]}


# --------------------------------------------------------------------------- #
# State changes
# --------------------------------------------------------------------------- #


def expire_due(conn) -> list[str]:
    """Reservations past expiresAt return their space immediately (no quarantine)."""
    rows = conn.execute(
        "SELECT site_id, site_code FROM site WHERE status = 'reserved' AND expires_at <= now() FOR UPDATE SKIP LOCKED"
    ).fetchall()
    for r in rows:
        conn.execute("DELETE FROM block WHERE site_id = %s", (r["site_id"],))
        conn.execute("UPDATE site SET status = 'expired', ended_at = now() WHERE site_id = %s", (r["site_id"],))
    return [r["site_code"] for r in rows]


def _check_reservation(site: dict[str, Any], reservation_id: str | None) -> None:
    if site["status"] != "reserved":
        raise IpamError("IPAM-SITE-STATE", f"Site {site['site_code']} is {site['status']}, not reserved", status_=site["status"])
    if reservation_id and str(site["reservation_id"]) != str(reservation_id):
        raise IpamError("IPAM-RESERVATION-MISMATCH", "reservationId doesn't match this site's reservation")
    if site["expires_at"] and site["expires_at"] <= datetime.now(timezone.utc):
        raise IpamError("IPAM-RESERVATION-EXPIRED", f"The reservation for {site['site_code']} has expired")


def confirm(conn, code: str, reservation_id: str | None, actor: str) -> dict[str, Any]:
    if not reservation_id:
        raise IpamError("IPAM-BAD-REQUEST", "reservationId is required to confirm")
    site = repo.live_site(conn, code, for_update=True)
    _check_reservation(site, reservation_id)
    site = conn.execute(
        """UPDATE site SET status = 'allocated', expires_at = NULL, confirmed_at = now(), confirmed_by = %s
           WHERE site_id = %s RETURNING *""",
        (actor, site["site_id"]),
    ).fetchone()
    conn.execute("UPDATE subnet SET status = 'active' WHERE site_id = %s", (site["site_id"],))
    return site


def extend(conn, code: str, days: int, actor: str) -> dict[str, Any]:
    cfg = repo.settings(conn)
    if not (1 <= days <= int(cfg["siteReservationMaxDays"])):
        raise IpamError("IPAM-BAD-REQUEST", f"days must be 1-{cfg['siteReservationMaxDays']}")
    site = repo.live_site(conn, code, for_update=True)
    _check_reservation(site, None)
    return conn.execute(
        "UPDATE site SET expires_at = now() + make_interval(days => %s) WHERE site_id = %s RETURNING *",
        (days, site["site_id"]),
    ).fetchone()


def release(conn, code: str, actor: str) -> dict[str, Any]:
    site = repo.live_site(conn, code, for_update=True)
    if site["status"] != "reserved":
        raise IpamError(
            "IPAM-SITE-STATE",
            f"Site {code} is {site['status']}; only a reservation can be released (retire is a later phase)",
        )
    conn.execute("DELETE FROM block WHERE site_id = %s", (site["site_id"],))
    return conn.execute(
        "UPDATE site SET status = 'released', ended_at = now() WHERE site_id = %s RETURNING *", (site["site_id"],)
    ).fetchone()


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #


def summary(conn, site: dict[str, Any]) -> dict[str, Any]:
    blocks = conn.execute(
        "SELECT block_key, cidr, vrf_key, pool_key FROM block WHERE site_id = %s ORDER BY block_key", (site["site_id"],)
    ).fetchall()
    tpl = None
    if site["template_key"]:
        tv = tsvc.get_version(conn, site["template_key"], site["template_version"])
        tpl = _template_ref(tv)
    out = {
        "siteId": str(site["site_id"]),
        "siteCode": site["site_code"],
        "countryCode": site["country_code"],
        "status": site["status"],
        "allocationState": "reserved" if site["status"] == "reserved" else ("confirmed" if site["status"] in ("allocated", "active") else site["status"]),
        "template": tpl,
        "conformance": "conformant" if tpl else "legacy",
        "blocks": [{"blockKey": b["block_key"], "cidr": str(b["cidr"]), "vrf": b["vrf_key"], "pool": b["pool_key"]} for b in blocks],
        "clientName": site["client_name"],
        "createdAt": site["created_at"],
        "confirmedAt": site["confirmed_at"],
        "endedAt": site["ended_at"],
    }
    if site["status"] == "reserved":
        out["reservation"] = {"reservationId": str(site["reservation_id"]), "expiresAt": site["expires_at"], "reservedBy": site["reserved_by"]}
    code_row = conn.execute("SELECT status, non_standard FROM site_code WHERE code = %s", (site["site_code"],)).fetchone()
    if code_row:
        out["siteCodeStatus"] = code_row["status"]
        out["nonStandardSiteCode"] = code_row["non_standard"]
    return out


def design(conn, site: dict[str, Any], *, section: str | None = None, vlan_key: str | None = None, include_hosts: bool = True) -> dict[str, Any]:
    sql = """SELECT s.*, v.vlan_name, v.class, v.security_zone FROM subnet s LEFT JOIN vlan v USING (vlan_key)
             WHERE s.site_id = %s"""
    params: list[Any] = [site["site_id"]]
    if section:
        sql += " AND upper(s.section) = upper(%s)"
        params.append(section)
    if vlan_key:
        sql += " AND s.vlan_key = %s"
        params.append(vlan_key)
    subnets = conn.execute(sql + " ORDER BY s.cidr", params).fetchall()
    hosts: dict[Any, list[dict[str, Any]]] = {}
    if include_hosts:
        for h in conn.execute(
            """SELECT * FROM ip_record WHERE site_id = %s AND status <> 'gateway' ORDER BY ip""", (site["site_id"],)
        ).fetchall():
            hosts.setdefault(h["subnet_id"], []).append(
                {
                    "roleCode": h["role_code"],
                    "member": h["member_name"],
                    "hostPosition": h["host_position"],
                    "octetUsed": h["octet_used"],
                    "ip": str(h["ip"]),
                    "hostname": h["hostname"],
                    "status": h["status"],
                }
            )
    networks = [
        network_view(
            {
                "section": s["section"],
                "vrf": s["vrf_key"],
                "relativeCidr": str(s["relative_cidr"]),
                "_cidr": IPv4Network(str(s["cidr"])),
                "_gateway": IPv4Address(str(s["gateway"]).split("/")[0]),
                "vlanKey": s["vlan_key"],
                "vlanId": s["vlan_id"],
                "vlanName": s["vlan_name"],
                "vlanClass": s["class"],
                "securityZone": s["security_zone"],
                "status": s["status"],
                "hosts": hosts.get(s["subnet_id"], []),
            },
            include_hosts,
        )
        for s in subnets
    ]
    return {**summary(conn, site), "subnetCount": len(networks), "networks": networks}


def preview(conn, key: str, version: int | None, base_ip: str | None, pool: str | None) -> dict[str, Any]:
    if version is None:
        row = conn.execute(
            """SELECT * FROM template_version WHERE template_key = %s
               ORDER BY (state = 'RELEASED') DESC, version DESC LIMIT 1""",
            (key,),
        ).fetchone()
        if row is None:
            raise IpamError("IPAM-TEMPLATE-NOT-FOUND", f"No template {key}", templateKey=key)
    else:
        row = tsvc.get_version(conn, key, version)
    layout = layout_from_content(row["content"])
    bases, pools = _resolve_bases(conn, layout, {"baseIp": base_ip, "pool": pool})
    networks = materialise(conn, layout, bases)
    return {
        "persisted": False,
        "template": _template_ref(row),
        "blocks": [
            {"blockKey": k, "cidr": str(v), "pool": pools[k], "nonBinding": pools[k] is not None} for k, v in bases.items()
        ],
        "summary": layout.summary(),
        "networks": [network_view(n) for n in networks],
    }
