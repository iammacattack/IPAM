"""Search, next-available, and the MCP server driven over stdio exactly as Claude would."""

from __future__ import annotations

import json
import os
import sys

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from helpers import API_KEY, BASE_URL, make_client


@pytest.fixture(scope="module")
def api():
    with make_client("pytest/search", API_KEY) as c:
        yield c


@pytest.fixture(scope="module")
def x9(api):
    s = api.get("/sites/X9")
    assert s.status_code == 200 and s.json()["status"] == "allocated", "Workflow 2 creates X9"
    p2 = ".".join(s.json()["blocks"][0]["cidr"].split(".")[:2])
    return p2


# ------------------------------------------------------------------ API

def test_search_by_ip_finds_site_subnet_and_host(api, x9):
    r = api.get("/search", params={"q": f"{x9}.13.61"}).json()
    assert r["subnets"][0]["siteCode"] == "X9" and r["subnets"][0]["vlanKey"] == "DCS-SERVERS" and r["subnets"][0]["cidr"] == f"{x9}.13.0/24"
    assert r["addresses"][0]["member"] == "WDC01" and r["addresses"][0]["hostname"] == "AUX9OTWDC01"


def test_search_by_text(api, x9):
    r = api.get("/search", params={"q": "VLAN_OT_SERVER"}).json()
    assert [v["vlanKey"] for v in r["vlans"]] == ["DCS-SERVERS"]
    r = api.get("/search", params={"q": "2013"}).json()
    assert any(v["vlanKey"] == "DCS-SERVERS" for v in r["vlans"])
    r = api.get("/search", params={"q": "AUX9OTWDC"}).json()
    assert r["hosts"][0]["ip"] == f"{x9}.13.61"
    r = api.get("/search", params={"q": "X9"}).json()
    assert r["sites"][0]["siteCode"] == "X9" and r["sites"][0]["blocks"] == [f"{x9}.0.0/16"]
    r = api.get("/search", params={"q": f"{x9}.80.0/22"}).json()
    assert r["subnets"][0]["vlanKey"] == "DCS-SECURITY"


def test_next_available(api, x9):
    r = api.get("/sites/X9/roles/WDC/next-available", params={"vlan": "VLAN_OT_SERVER"}).json()
    assert r["nonBinding"] is True
    # WDC01 was assigned to a machine in Workflow 3, so the next DC is WDC02
    assert r["results"][0]["member"] == "WDC02" and r["results"][0]["ip"] == f"{x9}.13.62"
    r = api.get("/sites/X9/roles/MSS/next-available").json()
    assert r["results"][0]["member"] == "MSS01"
    assert api.get("/sites/X9/roles/NOPE/next-available").json()["code"] == "IPAM-ROLE-UNKNOWN"


# ------------------------------------------------------------------ MCP over stdio

def run_mcp(calls: list[tuple[str, dict]]) -> tuple[list[str], list]:
    async def main():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "ipam_mcp"],
            env={**os.environ, "IPAM_URL": BASE_URL, "IPAM_API_KEY": API_KEY, "IPAM_CLIENT_NAME": "ClaudeCowork-MCP/test"},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                assert "IPAM" in (init.instructions or "")
                tools = await session.list_tools()
                results = [await session.call_tool(name, args) for name, args in calls]
                return [t.name for t in tools.tools], results, tools.tools
    return anyio.run(main)


def payload(result) -> dict:
    assert not result.isError, result.content[0].text
    return result.structuredContent if result.structuredContent else json.loads(result.content[0].text)


def test_mcp_tools(x9):
    names, results, tools = run_mcp([
        ("ipam_get_vlan_at_site", {"site_code": "x9", "vlan": "VLAN_OT_SERVER"}),
        ("ipam_get_vlan_at_site", {"site_code": "X9", "vlan": "VLAN_OT_SERVER", "field": "gateway"}),
        ("ipam_find_vlans", {"query": "server"}),
        ("ipam_get_vlan", {"vlan": "VLAN_OT_SERVER"}),
        ("ipam_list_site_vlans", {"site_code": "X9", "section": "CORP"}),
        ("ipam_lookup_host", {"site_code": "X9", "host": "WDC01", "vlan": "VLAN_OT_SERVER"}),
        ("ipam_next_available", {"site_code": "X9", "role_code": "WDC", "vlan": "DCS-SERVERS"}),
        ("ipam_search", {"query": f"{x9}.81.10"}),
        ("ipam_list_templates", {}),
        ("ipam_preview_template", {"template_key": "EXAMPLE-NET-10", "base_ip": "10.250.0.0"}),
        ("ipam_get_vlan_at_site", {"site_code": "X9", "vlan": "NO_SUCH_VLAN"}),
    ])
    assert set(names) >= {"ipam_find_vlans", "ipam_get_vlan", "ipam_get_vlan_at_site", "ipam_list_site_vlans", "ipam_lookup_host",
                          "ipam_next_available", "ipam_search", "ipam_list_sites", "ipam_get_site", "ipam_list_templates", "ipam_preview_template"}
    assert all(t.annotations and t.annotations.readOnlyHint for t in tools), "every tool is read-only"

    at_site = payload(results[0])
    assert at_site["cidr"] == f"{x9}.13.0/24" and at_site["gateway"] == f"{x9}.13.1" and at_site["mask"] == "255.255.255.0"
    assert at_site["dnsServers"] == f"{x9}.13.61,{x9}.13.62"
    assert {h["member"] for h in at_site["hosts"]} >= {"WDC01", "WDC02"}
    assert payload(results[1])["value"] == f"{x9}.13.1"
    assert {"CORP-SERVERS", "DCS-SERVERS"} <= {v["vlanKey"] for v in payload(results[2])["vlans"]}
    v = payload(results[3])
    assert v["vlanKey"] == "DCS-SERVERS" and v["vlanId"] == 2013 and v["usage"]["inUse"]
    corp = payload(results[4])
    assert corp["count"] >= 24 and all(n["section"] == "CORP" for n in corp["networks"])
    assert payload(results[5])["ip"] == f"{x9}.13.61"
    assert payload(results[6])["results"][0]["ip"] == f"{x9}.13.62"
    assert payload(results[7])["addresses"][0]["member"] == "NVR01"
    assert any(t["templateKey"] == "EXAMPLE-NET-10" for t in payload(results[8])["templates"])
    prev = payload(results[9])
    assert prev["blocks"][0]["cidr"] == "10.250.0.0/16" and prev["summary"]["subnetCount"] == 265
    # errors come back as a readable tool error, not a crash
    assert results[10].isError and "IPAM-VLAN-UNKNOWN" in results[10].content[0].text


def test_mcp_calls_are_audited_as_the_mcp_client(api, x9):
    run_mcp([("ipam_get_vlan_at_site", {"site_code": "X9", "vlan": "DCS-SECURITY", "field": "cidr"})])
    events = api.get("/audit", params={"clientName": "ClaudeCowork-MCP/test", "limit": 20}).json()
    assert any(e["action"] == "lookup.vlan" and e["siteCode"] == "X9" for e in events)
