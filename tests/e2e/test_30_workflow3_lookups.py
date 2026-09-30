"""Workflows 3 and 3a (spec §17.3, §17.3a): IaC resolves [VLAN_OT_SERVER] + [WDC01] and VLAN attributes at X9."""

from __future__ import annotations

import time

import pytest

from helpers import API_KEY, make_client

TEXT = {"Accept": "text/plain"}


@pytest.fixture(scope="module")
def iac():
    with make_client("Ansible/site-build", API_KEY) as c:
        yield c


@pytest.fixture(scope="module")
def x9(iac):
    """X9 as left by Workflow 2 (confirmed). Deploys and confirms it if this module runs alone."""
    r = iac.get("/sites/X9")
    if r.status_code != 200 or r.json()["status"] not in ("allocated", "active"):
        r = iac.post("/sites", json={"siteCode": "X9", "countryCode": "AU", "templateKey": "EXAMPLE-NET-10"})
        assert r.status_code == 201, r.text
        iac.post("/sites/X9:confirm", json={"reservationId": r.json()["reservation"]["reservationId"]}).raise_for_status()
        r = iac.get("/sites/X9")
    site = r.json()
    a, b = site["blocks"][0]["cidr"].split(".")[:2]
    return {"site": site, "p2": f"{a}.{b}"}


def test_host_token_resolves_via_alias(iac, x9):
    r = iac.get("/lookup/host-ip", params={"site": "X9", "vlan": "VLAN_OT_SERVER", "host": "WDC01"}, headers=TEXT)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert r.text == f"{x9['p2']}.13.61"

    j = iac.get("/lookup/host-ip", params={"site": "X9", "vlan": "VLAN_OT_SERVER", "host": "WDC01"}).json()
    assert j["vlanKey"] == "DCS-SERVERS" and j["octetUsed"] == "primary" and j["siteStatus"] == "allocated"


def test_lookup_errors(iac, x9):
    r = iac.get("/lookup/host-ip", params={"site": "X9", "vlan": "NO_SUCH_VLAN", "host": "WDC01"})
    assert r.status_code == 404 and r.json()["code"] == "IPAM-VLAN-UNKNOWN"
    r = iac.get("/lookup/host-ip", params={"site": "X9", "vlan": "SERVERS", "host": "WDC01"})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-ALIAS-AMBIGUOUS"
    assert set(r.json()["candidates"]) == {"CORP-SERVERS", "DCS-SERVERS"}
    r = iac.get("/lookup/host-ip", params={"site": "X9", "vlan": "VLAN_OT_SERVER", "host": "NVR01"})
    assert r.status_code == 404 and r.json()["code"] == "IPAM-HOST-NOT-ON-VLAN"
    # WDC01 lives on CORP-SERVERS and DCS-SERVERS, so a lookup without a VLAN must say which
    r = iac.get("/lookup/host-ip", params={"site": "X9", "host": "WDC01"})
    assert r.status_code == 400 and r.json()["code"] == "IPAM-VLAN-REQUIRED"


def test_assign_claims_the_address(iac, x9):
    params = {"site": "X9", "vlan": "VLAN_OT_SERVER", "host": "WDC01", "resolve": "assign", "hostname": "AUX9OTWDC01"}
    r = iac.get("/lookup/host-ip", params=params)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "assigned" and r.json()["hostname"] == "AUX9OTWDC01"
    # the same machine asking again is fine
    assert iac.get("/lookup/host-ip", params=params).status_code == 200
    # a different machine is refused, and told who holds it
    r = iac.get("/lookup/host-ip", params={**params, "hostname": "AUX9OTWDC99"})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-HOST-ALREADY-ASSIGNED"
    assert r.json()["currentHostname"] == "AUX9OTWDC01"


def test_assign_refused_until_confirmed(iac):
    r = iac.post("/sites", json={"siteCode": "X4", "templateKey": "EXAMPLE-NET-10"})
    assert r.status_code == 201
    try:
        # lookups work while reserved...
        ip = iac.get("/lookup/host-ip", params={"site": "X4", "vlan": "VLAN_OT_SERVER", "host": "WDC02"}, headers=TEXT)
        assert ip.status_code == 200 and ip.text.endswith(".13.62")
        # ...but nothing can be built on space that might lapse
        r = iac.get("/lookup/host-ip", params={"site": "X4", "vlan": "VLAN_OT_SERVER", "host": "WDC02",
                                               "resolve": "assign", "hostname": "AUX4OTWDC02"})
        assert r.status_code == 409 and r.json()["code"] == "IPAM-SITE-NOT-CONFIRMED"
    finally:
        iac.post("/sites/X4:release")


def test_vlan_attribute_fields(iac, x9):
    p2 = x9["p2"]
    expected = {
        "gateway": f"{p2}.13.1",
        "mask": "255.255.255.0",
        "prefix": "24",
        "networkPortion": f"{p2}.13",
        "dnsServers": f"{p2}.13.61,{p2}.13.62",
        "vlanId": "2013",
        "vlanName": "v2013-DCS-SERVERS",
        "broadcast": f"{p2}.13.255",
    }
    for field, value in expected.items():
        r = iac.get("/lookup/vlan", params={"site": "X9", "vlan": "VLAN_OT_SERVER", "field": field}, headers=TEXT)
        assert r.status_code == 200 and r.text == value, (field, r.text)


def test_supernet_and_index(iac, x9):
    p2 = x9["p2"]
    a = iac.get("/lookup/vlan", params={"site": "X9", "vlan": "DCS-SECURITY"}).json()
    assert a["cidr"] == f"{p2}.80.0/22" and a["networkPortion"] == f"{p2}.80" and a["spansThirdOctets"] == "80-83"
    r = iac.get("/lookup/vlan", params={"site": "X9", "vlan": "DCS-SECURITY", "field": "networkPortion", "index": 1}, headers=TEXT)
    assert r.text == f"{p2}.81"
    r = iac.get("/lookup/host-ip", params={"site": "X9", "vlan": "DCS-SECURITY", "host": "NVR01"}, headers=TEXT)
    assert r.text == f"{p2}.81.10"


def test_validate_octet(iac, x9):
    ok = iac.get("/lookup/vlan", params={"site": "X9", "vlan": "VLAN_OT_SERVER", "field": "validateOctet", "octet": 70}).json()
    assert ok["value"]["usable"] is True
    held = iac.get("/lookup/vlan", params={"site": "X9", "vlan": "VLAN_OT_SERVER", "field": "validateOctet", "octet": 62}).json()
    assert held["value"]["usable"] is False and held["value"]["heldBy"] == "WDC02"


def test_unknown_field(iac, x9):
    r = iac.get("/lookup/vlan", params={"site": "X9", "vlan": "VLAN_OT_SERVER", "field": "colour"})
    assert r.status_code == 400 and r.json()["code"] == "IPAM-FIELD-UNKNOWN"
    assert "gateway" in r.json()["validFields"]


def test_resolve_tokens_batch(iac, x9):
    p2 = x9["p2"]
    body = {
        "site": "X9",
        "tokens": [
            {"vlan": "VLAN_OT_SERVER", "host": "WDC01"},
            {"vlan": "VLAN_OT_SERVER", "field": "gateway"},
            {"vlan": "VLAN_OT_SERVER", "field": "mask"},
            {"vlan": "VLAN_OT_SERVER", "field": "prefix"},
            {"vlan": "VLAN_OT_SERVER", "field": "networkPortion"},
            {"vlan": "VLAN_OT_SERVER", "field": "dnsServers"},
            {"vlan": "NOPE", "field": "gateway"},
        ],
    }
    r = iac.post("/lookup:resolve-tokens", json=body)
    assert r.status_code == 200
    out = r.json()
    values = [x.get("value") for x in out["results"]]
    assert values[:6] == [f"{p2}.13.61", f"{p2}.13.1", "255.255.255.0", 24, f"{p2}.13", f"{p2}.13.61,{p2}.13.62"]
    assert out["results"][6]["error"]["code"] == "IPAM-VLAN-UNKNOWN"
    assert out["resolved"] == 6 and out["failed"] == 1


def test_lookups_are_audited(api, iac, x9):
    # The audit log is never cleared, so look only at this call's own row.
    r = iac.get("/lookup/vlan", params={"site": "X9", "vlan": "VLAN_OT_SERVER", "field": "gateway"})
    events = api.get("/audit", params={"requestId": r.headers["X-Request-Id"]}).json()
    assert len(events) == 1
    e = events[0]
    assert e["action"] == "lookup.vlan" and e["siteCode"] == "X9"
    assert e["objectKey"] == "DCS-SERVERS.gateway" and "VLAN_OT_SERVER" in e["query"]
    assert e["clientName"] == "Ansible/site-build"


def test_host_lookup_p95_under_200ms(iac, x9):
    """ADR T6 / Workflow 3 pass criterion."""
    timings = []
    for _ in range(60):
        start = time.perf_counter()
        r = iac.get("/lookup/host-ip", params={"site": "X9", "vlan": "VLAN_OT_SERVER", "host": "WDC02"}, headers=TEXT)
        timings.append((time.perf_counter() - start) * 1000)
        assert r.status_code == 200
    timings.sort()
    p95 = timings[int(len(timings) * 0.95) - 1]
    print(f"host lookup p95 = {p95:.1f} ms")
    assert p95 < 200
