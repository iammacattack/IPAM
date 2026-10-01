"""Global search and next-available (spec §8.2): used by the UI, scripts and the MCP server."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from .. import repo
from ..audit import note
from ..auth import Principal, require
from ..config import LIVE_SITE_STATUSES
from ..db import tx
from ..errors import IpamError

router = APIRouter(tags=["lookups"])
LIVE = list(LIVE_SITE_STATUSES)


def _addr(v: Any) -> str:
    return str(v).split("/")[0]


@router.get("/search")
def search(request: Request, q: str = Query(..., min_length=1, description="An IP, CIDR, hostname, VLAN key/name/ID/alias, site code or template"),
           limit: int = Query(25, ge=1, le=200), _: Principal = Depends(require("read"))):
    """Find anything by what you know about it. An IP returns the site, subnet, VLAN and host it belongs to."""
    note(request, "search", objectKey=q[:80])
    text = q.strip()
    out: dict[str, list[dict[str, Any]]] = {"addresses": [], "subnets": [], "hosts": [], "vlans": [], "sites": [], "templates": []}
    with tx() as conn:
        ip = net = None
        try:
            ip = ip_address(text)
        except ValueError:
            try:
                net = ip_network(text, strict=False)
            except ValueError:
                pass

        subnet_sql = """SELECT s.cidr, s.gateway, s.section, s.vrf_key, s.vlan_key, s.vlan_id, v.vlan_name, t.site_code, t.status
                        FROM subnet s JOIN site t USING (site_id) LEFT JOIN vlan v USING (vlan_key)
                        WHERE t.status = ANY(%s) AND {cond} ORDER BY s.cidr LIMIT %s"""
        if ip is not None or net is not None:
            target = str(ip) if ip is not None else str(net)
            op = ">>=" if ip is not None else "&&"
            for s in conn.execute(subnet_sql.format(cond=f"s.cidr {op} %s::inet"), (LIVE, target, limit)).fetchall():
                out["subnets"].append({"siteCode": s["site_code"], "siteStatus": s["status"], "cidr": str(s["cidr"]), "gateway": _addr(s["gateway"]),
                                       "section": s["section"], "vrf": s["vrf_key"], "vlanKey": s["vlan_key"], "vlanId": s["vlan_id"], "vlanName": s["vlan_name"]})
            if ip is not None:
                for r in conn.execute(
                    """SELECT i.*, s.cidr, s.vlan_key, t.site_code FROM ip_record i JOIN subnet s USING (subnet_id) JOIN site t ON t.site_id = i.site_id
                       WHERE i.ip = %s::inet AND t.status = ANY(%s)""", (str(ip), LIVE)
                ).fetchall():
                    out["addresses"].append({"ip": _addr(r["ip"]), "siteCode": r["site_code"], "subnet": str(r["cidr"]), "vlanKey": r["vlan_key"],
                                             "status": r["status"], "roleCode": r["role_code"], "member": r["member_name"], "hostname": r["hostname"]})
                if not out["subnets"]:
                    blk = conn.execute(
                        "SELECT b.cidr, t.site_code, t.status FROM block b JOIN site t USING (site_id) WHERE b.cidr >>= %s::inet", (str(ip),)
                    ).fetchone()
                    if blk:
                        out["addresses"].append({"ip": str(ip), "siteCode": blk["site_code"], "block": str(blk["cidr"]), "status": f"in site block ({blk['status']}), no subnet"})
        else:
            like = f"%{text}%"
            for r in conn.execute(
                """SELECT i.ip, i.hostname, i.member_name, i.role_code, i.status, s.cidr, s.vlan_key, t.site_code
                   FROM ip_record i JOIN subnet s USING (subnet_id) JOIN site t ON t.site_id = i.site_id
                   WHERE t.status = ANY(%s) AND i.hostname ILIKE %s ORDER BY i.hostname LIMIT %s""", (LIVE, like, limit)
            ).fetchall():
                out["hosts"].append({"hostname": r["hostname"], "ip": _addr(r["ip"]), "siteCode": r["site_code"], "vlanKey": r["vlan_key"],
                                     "member": r["member_name"], "roleCode": r["role_code"], "status": r["status"]})
            id_match = int(text) if text.isdigit() else -1
            for v in conn.execute(
                """SELECT DISTINCT v.* FROM vlan v LEFT JOIN vlan_alias a USING (vlan_key)
                   WHERE v.vlan_key ILIKE %s OR v.vlan_name ILIKE %s OR a.alias ILIKE %s OR v.vlan_id = %s OR coalesce(v.description, '') ILIKE %s
                   ORDER BY v.vlan_key LIMIT %s""", (like, like, like, id_match, like, limit)
            ).fetchall():
                out["vlans"].append({"vlanKey": v["vlan_key"], "vlanId": v["vlan_id"], "vlanName": v["vlan_name"], "class": v["class"],
                                     "securityZone": v["security_zone"], "status": v["status"]})
            for s in conn.execute(
                "SELECT site_code, status, template_key, template_version FROM site WHERE site_code ILIKE %s AND status = ANY(%s) ORDER BY site_code LIMIT %s",
                (like, LIVE, limit),
            ).fetchall():
                blocks = [str(b["cidr"]) for b in conn.execute(
                    "SELECT b.cidr FROM block b JOIN site t USING (site_id) WHERE t.site_code = %s AND t.status = ANY(%s)", (s["site_code"], LIVE))]
                out["sites"].append({"siteCode": s["site_code"], "status": s["status"], "blocks": blocks,
                                     "template": f"{s['template_key']}@v{s['template_version']}" if s["template_key"] else None})
            for t in conn.execute("SELECT template_key, description FROM template WHERE template_key ILIKE %s ORDER BY 1 LIMIT %s", (like, limit)):
                out["templates"].append({"templateKey": t["template_key"], "description": t["description"]})
    out["total"] = sum(len(v) for v in out.values() if isinstance(v, list))
    return {"query": text, **out}


@router.get("/sites/{site_code}/roles/{role_code}/next-available")
def next_available(request: Request, site_code: str, role_code: str, vlan: str | None = None, _: Principal = Depends(require("read"))):
    """Non-binding: the next free instance or address for a host type at a site. Fixed members come first
    (the next one not yet assigned to a machine), then range members (the first octet nobody holds)."""
    code, role = site_code.upper(), role_code.upper()
    note(request, "lookup.next_available", objectType="host-role", objectKey=role, siteCode=code)
    with tx() as conn:
        site = repo.live_site(conn, code)
        r = conn.execute("SELECT * FROM host_role WHERE role_code = %s", (role,)).fetchone()
        if r is None:
            raise IpamError("IPAM-ROLE-UNKNOWN", f"No host pool {role}", status=404)
        vlan_keys = [repo.resolve_vlan_key(conn, vlan)] if vlan else list(r["vlan_keys"])
        members = conn.execute("SELECT * FROM host_role_member WHERE role_code = %s ORDER BY ordinal", (role,)).fetchall()
        answers = []
        for vk in vlan_keys:
            sub = conn.execute("SELECT * FROM subnet WHERE site_id = %s AND vlan_key = %s", (site["site_id"], vk)).fetchone()
            if sub is None:
                continue
            held = {_addr(x["ip"]): x for x in conn.execute("SELECT * FROM ip_record WHERE subnet_id = %s", (sub["subnet_id"],)).fetchall()}
            choice = None
            for m in members:
                if m["kind"] == "fixed":
                    rec = next((x for x in held.values() if (x["member_name"] or "").upper() == m["name"]), None)
                    if rec and rec["status"] != "assigned":
                        choice = {"kind": "fixed", "member": m["name"], "ip": _addr(rec["ip"]), "currentStatus": rec["status"]}
                        break
            if choice is None:
                cidr = IPv4Network(str(sub["cidr"]))
                base3 = int(cidr.network_address) & ~0xFF
                for m in members:
                    if m["kind"] != "range":
                        continue
                    for octet in range(m["range_start"], m["range_end"] + 1):
                        cand = IPv4Address(base3 + octet)
                        if cand in cidr and cand not in (cidr.network_address, cidr.broadcast_address) and str(cand) not in held:
                            choice = {"kind": "range", "member": m["name"], "ip": str(cand), "currentStatus": "free"}
                            break
                    if choice:
                        break
            answers.append({"vlanKey": vk, "subnet": str(sub["cidr"]), **(choice or {"ip": None, "note": "every position is taken"})})
        if not answers:
            raise IpamError("IPAM-HOST-NOT-ON-VLAN", f"{role} doesn't live on any VLAN bound at {code}", status=404, vlanKeys=vlan_keys)
    return {"siteCode": code, "roleCode": role, "nonBinding": True, "results": answers}
