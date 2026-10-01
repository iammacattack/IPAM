"""IPAM MCP server (spec §9): read-only tools over the IPAM API, stdio transport.

No tool here can deploy, retire or delete a site, or change templates or the library. Those stay
with people signed in to the IPAM UI with 2FA. Every call is audited by IPAM under the API key's
owner, with client name ClaudeCowork-MCP.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from .client import Ipam, IpamError

INSTRUCTIONS = """\
IPAM is the authoritative record of IP address allocations: sites, their address blocks, subnets,
VLANs and standard host addresses (e.g. domain controller WDC01 is .61 on its VLAN).

Ask by name, not by address. A site is a short code such as X9 or B1. A VLAN is a key such as
DCS-SERVERS, or an alias such as VLAN_OT_SERVER. A host is a host-pool member such as WDC01.

- "What's the subnet for VLAN X at site Y?" -> ipam_get_vlan_at_site
- "What's WDC01's IP at X9?" -> ipam_lookup_host
- "What VLANs exist for ...?" -> ipam_find_vlans; details and usage of one VLAN -> ipam_get_vlan
- "All VLANs/subnets at a site" -> ipam_list_site_vlans
- "Where does 10.1.13.61 belong?" or any free-text lookup -> ipam_search
- "Next free DC address at X9" -> ipam_next_available (it doesn't reserve anything)

These tools only read. To reserve, confirm, retire sites or change the library, tell the user to use
the IPAM web UI. Quote addresses exactly as returned; never compute them yourself.
"""

logging.getLogger("httpx").setLevel(logging.WARNING)  # don't log every API call to Claude's MCP log
mcp = FastMCP("ipam", instructions=INSTRUCTIONS, log_level="WARNING")
api = Ipam()
READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

Site = Annotated[str, Field(description="Site code, e.g. X9 or B1")]
Vlan = Annotated[str, Field(description="VLAN key (e.g. DCS-SERVERS) or alias (e.g. VLAN_OT_SERVER)")]


def _q(part: str) -> str:
    return quote(part.strip(), safe="")


def call(path: str, **params: Any) -> Any:
    try:
        return api.get(path, **params)
    except IpamError as err:
        raise ToolError(err.describe()) from err


def _network_row(n: dict[str, Any]) -> dict[str, Any]:
    return {k: n.get(k) for k in ("section", "vlanKey", "vlanId", "vlanName", "cidr", "gateway", "mask", "prefix", "networkPortion")}


# --------------------------------------------------------------------------- VLAN library


@mcp.tool(annotations=READ)
def ipam_find_vlans(
    query: Annotated[str | None, Field(description="Text to match in the key, name, alias or description, or a VLAN ID")] = None,
    vlan_class: Annotated[str | None, Field(description="Filter by class, e.g. CORP, DCS, CSMS")] = None,
    include_generated: Annotated[bool, Field(description="Include VLANs a template's bulk rule generated (e.g. DCS-N014)")] = False,
    limit: Annotated[int, Field(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    """Search the VLAN library (the definitions shared by every site): key, ID, name, aliases, class, security zone."""
    vlans = call("/vlans", **({"class": vlan_class} if vlan_class else {}))
    q = (query or "").strip().lower()
    out = []
    for v in vlans:
        generated = v["vlanKey"].rsplit("-", 1)[-1].startswith("N") and v["vlanKey"].rsplit("-", 1)[-1][1:4].isdigit()
        if generated and not include_generated:
            continue
        hay = " ".join([v["vlanKey"], v["vlanName"] or "", " ".join(v.get("aliases") or []), v.get("description") or "", str(v.get("vlanId") or "")]).lower()
        if q and q not in hay and not (q.isdigit() and str(v.get("vlanId")) == q):
            continue
        out.append({k: v.get(k) for k in ("vlanKey", "vlanId", "vlanName", "aliases", "class", "securityZone", "status", "description")})
    return {"count": len(out), "vlans": out[:limit], "truncated": len(out) > limit}


@mcp.tool(annotations=READ)
def ipam_get_vlan(vlan: Vlan) -> dict[str, Any]:
    """One VLAN's library definition (ID, name, aliases, class, security zone, status) and where it's used:
    template versions, live sites and host pools."""
    v = call(f"/vlans/{_q(vlan)}")
    v["usage"] = call(f"/vlans/{_q(v['vlanKey'])}/usage")
    return v


# --------------------------------------------------------------------------- VLANs and subnets at a site


@mcp.tool(annotations=READ)
def ipam_get_vlan_at_site(
    site_code: Site,
    vlan: Vlan,
    field: Annotated[str | None, Field(description=(
        "Return just one attribute: gateway, mask, prefix, cidr, network, networkPortion (3OCT), twoOctets, "
        "spansThirdOctets, broadcast, firstUsable, lastUsable, vlanId, vlanName, dnsServers"))] = None,
) -> dict[str, Any]:
    """The subnet a VLAN has at a site, with all its attributes (CIDR, gateway, mask, prefix, network portion,
    broadcast, usable range, DNS servers) and the standard hosts in it. Use field= for a single value."""
    site = site_code.strip().upper()
    if field:
        r = call("/lookup/vlan", site=site, vlan=vlan, field=field)
        return {"siteCode": r["siteCode"], "vlanKey": r["vlanKey"], "field": r["field"], "value": r["value"], "siteStatus": r["siteStatus"]}
    attrs = call("/lookup/vlan", site=site, vlan=vlan)
    design = call(f"/sites/{_q(site)}/design", vlanKey=attrs["vlanKey"], include="hosts")
    hosts = design["networks"][0].get("hosts", []) if design.get("networks") else []
    attrs["hosts"] = [{k: h.get(k) for k in ("member", "roleCode", "ip", "hostname", "status", "octetUsed")} for h in hosts]
    return attrs


@mcp.tool(annotations=READ)
def ipam_list_site_vlans(
    site_code: Site,
    section: Annotated[str | None, Field(description="Only this section, e.g. CORP or DCS")] = None,
    bound_only: Annotated[bool, Field(description="Skip subnets with no VLAN assigned")] = True,
) -> dict[str, Any]:
    """Every VLAN-to-subnet mapping at a site (section, VLAN key/ID/name, CIDR, gateway, mask)."""
    d = call(f"/sites/{_q(site_code.upper())}/design", section=section, include="none")
    rows = [_network_row(n) for n in d["networks"] if n.get("vlanKey") or not bound_only]
    return {"siteCode": d["siteCode"], "status": d["status"], "blocks": d["blocks"], "count": len(rows), "networks": rows}


# --------------------------------------------------------------------------- hosts


@mcp.tool(annotations=READ)
def ipam_lookup_host(
    site_code: Site,
    host: Annotated[str | None, Field(description="Host-pool member, e.g. WDC01, NVR01")] = None,
    vlan: Annotated[str | None, Field(description="VLAN key or alias; needed when the member lives on several VLANs")] = None,
    role: Annotated[str | None, Field(description="Host pool code (e.g. WDC) - use with instance instead of host")] = None,
    instance: Annotated[int | None, Field(ge=1, description="Instance number within the role, e.g. 2 for the second DC")] = None,
) -> dict[str, Any]:
    """A standard host's IP address at a site, by member name (WDC01) or role + instance, with its subnet,
    gateway, hostname and status."""
    return call("/lookup/host-ip", site=site_code.upper(), host=host, vlan=vlan, role=role, instance=instance)


@mcp.tool(annotations=READ)
def ipam_next_available(
    site_code: Site,
    role_code: Annotated[str, Field(description="Host pool code, e.g. WDC, MSS, HYP")],
    vlan: Annotated[str | None, Field(description="Limit to one VLAN (key or alias)")] = None,
) -> dict[str, Any]:
    """The next free address for a host type at a site, e.g. 'next DC IP at X9'. Non-binding: it doesn't
    reserve anything, so tell the user to claim it in IPAM before building."""
    return call(f"/sites/{_q(site_code.upper())}/roles/{_q(role_code.upper())}/next-available", vlan=vlan)


# --------------------------------------------------------------------------- sites, search, templates


@mcp.tool(annotations=READ)
def ipam_search(query: Annotated[str, Field(description="An IP (10.1.13.61), CIDR, hostname, VLAN key/name/ID/alias, site code or template")]) -> dict[str, Any]:
    """Find anything. An IP returns the site, subnet, VLAN and host record it belongs to; text matches
    hostnames, VLANs, sites and templates."""
    return call("/search", q=query)


@mcp.tool(annotations=READ)
def ipam_list_sites(status: Annotated[str | None, Field(description="reserved, allocated, retired, ... (comma-separated); default: live sites")] = None) -> dict[str, Any]:
    """Sites with their status, address block(s) and template."""
    sites = call("/sites", status=status)
    rows = [{"siteCode": s["siteCode"], "status": s["status"], "blocks": [b["cidr"] for b in s["blocks"]],
             "template": f"{s['template']['key']}@v{s['template']['version']}" if s.get("template") else None,
             "createdAt": s["createdAt"]} for s in sites]
    return {"count": len(rows), "sites": rows}


@mcp.tool(annotations=READ)
def ipam_get_site(site_code: Site) -> dict[str, Any]:
    """One site's summary: status, block(s), template version, reservation or retirement details."""
    return call(f"/sites/{_q(site_code.upper())}")


@mcp.tool(annotations=READ)
def ipam_list_templates() -> dict[str, Any]:
    """Site network templates and their versions; only RELEASED versions can be deployed."""
    ts = call("/templates")
    return {"templates": [{"templateKey": t["templateKey"], "description": t["description"],
                           "versions": [{"version": v["version"], "state": v["state"],
                                         "subnets": (v.get("summary") or {}).get("subnetCount"), "liveSites": v.get("siteCount")} for v in t["versions"]]}
                          for t in ts]}


@mcp.tool(annotations=READ)
def ipam_preview_template(
    template_key: Annotated[str, Field(description="e.g. EXAMPLE-NET-10")],
    base_ip: Annotated[str | None, Field(description="e.g. 10.9.0.0; leave out to see the block the pool would pick next")] = None,
    version: Annotated[int | None, Field(ge=1)] = None,
) -> dict[str, Any]:
    """What a template would produce at a base IP: sections, subnet counts and every VLAN's subnet. Nothing is saved."""
    p = call(f"/templates/{_q(template_key.upper())}/preview", baseIp=base_ip, version=version)
    return {"template": p["template"], "blocks": p["blocks"], "summary": p["summary"],
            "networks": [_network_row(n) for n in p["networks"] if n.get("vlanKey")]}


def main() -> None:
    mcp.run()  # stdio


if __name__ == "__main__":
    main()
