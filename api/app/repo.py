"""Shared reads: settings, VLAN library, host pools, sites."""

from __future__ import annotations

from typing import Any

from nextdc_ipam_engine import HostPool

from .config import LIVE_SITE_STATUSES
from .errors import IpamError

DEFAULT_SETTINGS: dict[str, Any] = {
    "siteReservationDays": 14,
    "siteReservationMaxDays": 90,
    "avoidZeroAndBroadcastOctetsInSupernets": True,
    "twoPersonRelease": False,
    "dnsMembers": ["WDC01", "WDC02"],
    # Security (spec §16.3 defaults)
    "sessionIdleMinutes": 30,
    "sessionAbsoluteHours": 8,
    "maxFailedLogins": 5,
    "lockoutMinutes": 15,
    "mfaRequiredForRoles": ["admin"],
    "stepUpActions": ["templates.release", "sites.confirm", "sites.release", "users.manage", "apikeys.manage", "mfa.replace"],
    "stepUpWindowMinutes": 5,
    "retireQuarantineDays": 90,
}


def settings(conn) -> dict[str, Any]:
    rows = conn.execute("SELECT key, value FROM setting").fetchall()
    return {**DEFAULT_SETTINGS, **{r["key"]: r["value"] for r in rows}}


def vlans(conn, keys: list[str] | None = None) -> dict[str, dict[str, Any]]:
    if keys is None:
        rows = conn.execute("SELECT * FROM vlan").fetchall()
    else:
        rows = conn.execute("SELECT * FROM vlan WHERE vlan_key = ANY(%s)", (keys,)).fetchall()
    return {r["vlan_key"]: r for r in rows}


def host_pools(conn) -> list[HostPool]:
    roles = conn.execute("SELECT * FROM host_role ORDER BY role_code").fetchall()
    members = conn.execute("SELECT * FROM host_role_member ORDER BY role_code, ordinal").fetchall()
    by_role: dict[str, list[dict[str, Any]]] = {}
    for m in members:
        by_role.setdefault(m["role_code"], []).append(
            {
                "name": m["name"],
                "kind": m["kind"],
                "hostPosition": m["host_position"],
                "secondaryHostOctet": m["secondary_host_octet"],
                "rangeStart": m["range_start"],
                "rangeEnd": m["range_end"],
            }
        )
    return [
        HostPool.from_dict(
            {
                "roleCode": r["role_code"],
                "vlanKeys": list(r["vlan_keys"]),
                "offsetMode": r["offset_mode"],
                "members": by_role.get(r["role_code"], []),
            }
        )
        for r in roles
    ]


def resolve_vlan_key(conn, name: str) -> str:
    """VLAN key or alias -> key. Unknown is 404; an alias on several VLANs is 409 with candidates."""
    row = conn.execute("SELECT vlan_key FROM vlan WHERE upper(vlan_key) = upper(%s)", (name,)).fetchone()
    if row:
        return row["vlan_key"]
    hits = conn.execute(
        "SELECT DISTINCT vlan_key FROM vlan_alias WHERE upper(alias) = upper(%s) ORDER BY vlan_key", (name,)
    ).fetchall()
    if not hits:
        raise IpamError("IPAM-VLAN-UNKNOWN", f"No VLAN key or alias '{name}'", vlan=name)
    if len(hits) > 1:
        raise IpamError(
            "IPAM-ALIAS-AMBIGUOUS",
            f"Alias '{name}' matches more than one VLAN; use a VLAN key",
            vlan=name,
            candidates=[h["vlan_key"] for h in hits],
        )
    return hits[0]["vlan_key"]


def live_site(conn, site_code: str, *, for_update: bool = False) -> dict[str, Any]:
    sql = "SELECT * FROM site WHERE site_code = %s AND status = ANY(%s)"
    if for_update:
        sql += " FOR UPDATE"
    row = conn.execute(sql, (site_code.upper(), list(LIVE_SITE_STATUSES))).fetchone()
    if row is None:
        raise IpamError("IPAM-SITE-NOT-FOUND", f"No live site '{site_code}'", siteCode=site_code.upper())
    return row


def latest_site(conn, site_code: str) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT * FROM site WHERE site_code = %s
        ORDER BY (status = ANY(%s)) DESC, created_at DESC LIMIT 1
        """,
        (site_code.upper(), list(LIVE_SITE_STATUSES)),
    ).fetchone()
    if row is None:
        raise IpamError("IPAM-SITE-NOT-FOUND", f"No site '{site_code}'", siteCode=site_code.upper())
    return row
