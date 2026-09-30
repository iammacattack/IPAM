"""Name-based lookups (spec §8.2 lookups, §8.2.1, Workflows 3 and 3a).

Clients ask by site + VLAN name (or alias) + host-pool member, never by address.
Everything is answered from the site's materialised records, so a template
edited after deploy never changes what a site returns.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Any

from psycopg import errors as pg_errors

from nextdc_ipam_engine import ALL_FIELDS, EngineError, validate_octet, vlan_attributes

from .. import repo
from ..errors import IpamError


def _addr(value: Any) -> IPv4Address:
    return IPv4Address(str(value).split("/")[0])


def site_subnet(conn, site: dict[str, Any], vlan_key: str) -> dict[str, Any]:
    row = conn.execute(
        """SELECT s.*, v.vlan_name FROM subnet s LEFT JOIN vlan v USING (vlan_key)
           WHERE s.site_id = %s AND s.vlan_key = %s""",
        (site["site_id"], vlan_key),
    ).fetchone()
    if row is None:
        raise IpamError(
            "IPAM-VLAN-NOT-AT-SITE", f"VLAN {vlan_key} isn't bound at site {site['site_code']}",
            siteCode=site["site_code"], vlanKey=vlan_key,
        )
    return row


def _member_for_instance(conn, role: str, instance: int) -> str:
    rows = conn.execute(
        "SELECT name FROM host_role_member WHERE role_code = %s AND kind = 'fixed' ORDER BY ordinal", (role.upper(),)
    ).fetchall()
    if not rows:
        raise IpamError("IPAM-ROLE-UNKNOWN", f"No host role '{role}' with fixed members", roleCode=role)
    if not (1 <= instance <= len(rows)):
        raise IpamError("IPAM-BAD-REQUEST", f"Role {role} has {len(rows)} fixed instance(s)", roleCode=role)
    return rows[instance - 1]["name"]


def find_host(
    conn,
    site_code: str,
    *,
    vlan: str | None = None,
    host: str | None = None,
    role: str | None = None,
    instance: int | None = None,
    for_update: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns (site, ip record joined with its subnet)."""
    site = repo.live_site(conn, site_code)
    if host is None:
        if not role:
            raise IpamError("IPAM-BAD-REQUEST", "Give host=<member>, or role=<code>&instance=<n>")
        host = _member_for_instance(conn, role, instance or 1)

    sql = """SELECT r.*, s.cidr, s.gateway, s.vlan_key, s.vlan_id, s.section
             FROM ip_record r JOIN subnet s USING (subnet_id)
             WHERE r.site_id = %s AND upper(r.member_name) = upper(%s)"""
    params: list[Any] = [site["site_id"], host]
    vlan_key = None
    if vlan:
        vlan_key = repo.resolve_vlan_key(conn, vlan)
        sql += " AND s.vlan_key = %s"
        params.append(vlan_key)
    rows = conn.execute(sql + (" FOR UPDATE OF r" if for_update else ""), params).fetchall()

    if not rows:
        if vlan_key:
            site_subnet(conn, site, vlan_key)  # 404 if the VLAN isn't at this site at all
            raise IpamError(
                "IPAM-HOST-NOT-ON-VLAN",
                f"Host-pool member {host} isn't configured on {vlan_key}",
                siteCode=site["site_code"], vlanKey=vlan_key, host=host,
            )
        raise IpamError("IPAM-HOST-NOT-ON-VLAN", f"No host-pool member {host} at site {site['site_code']}", host=host)
    if len(rows) > 1:
        raise IpamError(
            "IPAM-VLAN-REQUIRED",
            f"{host} exists on more than one VLAN at {site['site_code']}; add vlan=",
            candidates=sorted(r["vlan_key"] for r in rows),
        )
    return site, rows[0]


def host_view(site: dict[str, Any], rec: dict[str, Any]) -> dict[str, Any]:
    return {
        "siteCode": site["site_code"],
        "siteStatus": site["status"],
        "vrf": rec["vrf_key"],
        "vlanKey": rec["vlan_key"],
        "vlanId": rec["vlan_id"],
        "roleCode": rec["role_code"],
        "member": rec["member_name"],
        "ip": str(_addr(rec["ip"])),
        "hostPosition": rec["host_position"],
        "octetUsed": rec["octet_used"],
        "subnet": str(rec["cidr"]),
        "gateway": str(_addr(rec["gateway"])),
        "hostname": rec["hostname"],
        "status": rec["status"],
    }


def assign(conn, site: dict[str, Any], rec: dict[str, Any], hostname: str | None, actor: str) -> dict[str, Any]:
    """resolve=assign: claim a reserved-pattern address for a named machine."""
    if site["status"] not in ("allocated", "active"):
        raise IpamError(
            "IPAM-SITE-NOT-CONFIRMED",
            f"Site {site['site_code']} is {site['status']}; confirm the allocation before assigning hosts",
            siteCode=site["site_code"],
        )
    if not hostname:
        raise IpamError("IPAM-BAD-REQUEST", "resolve=assign needs hostname=")
    hostname = hostname.strip().upper()
    if rec["status"] == "assigned":
        if (rec["hostname"] or "").upper() == hostname:
            return rec  # same machine asking again
        raise IpamError(
            "IPAM-HOST-ALREADY-ASSIGNED",
            f"{rec['member_name']} at {site['site_code']} is already assigned to {rec['hostname']}",
            currentHostname=rec["hostname"], ip=str(_addr(rec["ip"])),
        )
    try:
        with conn.transaction():
            updated = conn.execute(
                """UPDATE ip_record SET status = 'assigned', hostname = %s, assigned_at = now(), assigned_by = %s
                   WHERE ip_id = %s RETURNING *""",
                (hostname, actor, rec["ip_id"]),
            ).fetchone()
    except pg_errors.UniqueViolation as exc:
        raise IpamError("IPAM-HOSTNAME-IN-USE", f"Hostname {hostname} is already assigned elsewhere", hostname=hostname) from exc
    return {**rec, **updated}


def dns_servers(conn, cfg: dict[str, Any], subnet_id) -> list[str]:
    members = [m.upper() for m in cfg.get("dnsMembers") or []]
    if not members:
        return []
    rows = conn.execute(
        "SELECT member_name, ip FROM ip_record WHERE subnet_id = %s AND upper(member_name) = ANY(%s)",
        (subnet_id, members),
    ).fetchall()
    by_name = {r["member_name"].upper(): str(_addr(r["ip"])) for r in rows}
    return [by_name[m] for m in members if m in by_name]


def vlan_lookup(
    conn, site_code: str, vlan: str, field: str | None = None, index: int | None = None, octet: int | None = None
) -> tuple[dict[str, Any], dict[str, Any], Any]:
    """Returns (site, all attributes, requested value or None)."""
    if field is not None and field not in ALL_FIELDS:
        raise IpamError("IPAM-FIELD-UNKNOWN", f"Unknown field '{field}'", validFields=list(ALL_FIELDS))
    site = repo.live_site(conn, site_code)
    vlan_key = repo.resolve_vlan_key(conn, vlan)
    sub = site_subnet(conn, site, vlan_key)
    cidr = IPv4Network(str(sub["cidr"]))
    gw = _addr(sub["gateway"])
    cfg = repo.settings(conn)
    attrs: dict[str, Any] = {
        "siteCode": site["site_code"],
        "siteStatus": site["status"],
        "vrf": sub["vrf_key"],
        "vlanKey": vlan_key,
        "vlanId": sub["vlan_id"],
        "vlanName": sub["vlan_name"],
        **vlan_attributes(cidr, gw, index),
        "dnsServers": ",".join(dns_servers(conn, cfg, sub["subnet_id"])),
    }
    value: Any = None
    if field == "validateOctet":
        if octet is None:
            raise IpamError("IPAM-BAD-REQUEST", "field=validateOctet needs octet=")
        held = {
            _addr(r["ip"]): r["member_name"] or r["status"]
            for r in conn.execute("SELECT ip, member_name, status FROM ip_record WHERE subnet_id = %s", (sub["subnet_id"],)).fetchall()
        }
        result = validate_octet(
            cidr, gw, octet, index=index or 0, taken=held.keys(),
            avoid_zero_and_broadcast_in_supernets=bool(cfg["avoidZeroAndBroadcastOctetsInSupernets"]),
        )
        if result["reason"] == "taken":
            result["heldBy"] = held.get(IPv4Address(result["ip"]))
        value = result
    elif field is not None:
        value = attrs[field]
    return site, attrs, value


def resolve_tokens(conn, site_code: str, tokens: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Batch form for IaC: one round trip for a whole manifest."""
    out = []
    for t in tokens:
        entry: dict[str, Any] = {"input": t}
        try:
            if t.get("host"):
                _, rec = find_host(conn, site_code, vlan=t.get("vlan"), host=t["host"])
                entry["value"] = str(_addr(rec["ip"]))
                entry["kind"] = "host"
            elif t.get("vlan") and t.get("field"):
                _, _, value = vlan_lookup(conn, site_code, t["vlan"], t["field"], t.get("index"), t.get("octet"))
                entry["value"] = value
                entry["kind"] = "attribute"
            else:
                raise IpamError("IPAM-BAD-REQUEST", "Each token needs vlan + host, or vlan + field")
        except IpamError as err:
            entry["error"] = {"code": err.code, "message": err.message, **err.extra}
        except EngineError as err:
            entry["error"] = err.to_dict()
        out.append(entry)
    return out
