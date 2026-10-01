"""Library MACD: VLANs, host pools, address pools and VRFs - add, change, delete, and the in-use guards."""

from __future__ import annotations

import uuid

import psycopg
import pytest

from helpers import API_KEY, DATABASE_URL, make_client
from test_50_users_2fa import browser, enrol, make_user, sign_in


@pytest.fixture(scope="module")
def api():
    with make_client("pytest/library", API_KEY) as c:
        yield c


@pytest.fixture(scope="module")
def admin():
    """Pools and VRFs are Administrator-only (spec §3); API keys can never hold that, so use a signed-in admin."""
    user = make_user(["admin"])
    with browser() as c:
        sign_in(c, user)
        enrol(c)
        yield c


@pytest.fixture(scope="module")
def tag():
    return uuid.uuid4().hex[:5].upper()


@pytest.fixture(scope="module", autouse=True)
def cleanup(tag):
    yield
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute("DELETE FROM host_role WHERE role_code LIKE 'LT-%'")
        conn.execute("DELETE FROM vlan WHERE vlan_key LIKE 'LT-%'")
        conn.execute("DELETE FROM pool WHERE pool_key LIKE 'LT-%' AND parent_key IS NOT NULL")
        conn.execute("DELETE FROM pool WHERE pool_key LIKE 'LT-%'")
        conn.execute("DELETE FROM vrf WHERE vrf_key LIKE 'LT-%'")
        conn.execute("DELETE FROM app_user WHERE username LIKE 'pt-%'")


# ------------------------------------------------------------------ VLANs

def test_vlan_add_change_delete(api, tag):
    key = f"LT-{tag}-VLAN"
    r = api.post("/vlans", json={"vlanKey": key, "vlanId": 3901, "vlanName": f"v3901-{tag}", "aliases": ["LT_ONE"], "class": "CORP", "securityZone": "Internal"})
    assert r.status_code == 201, r.text
    r = api.patch(f"/vlans/{key}", json={"description": "changed", "aliases": ["LT_TWO", "LT_THREE"], "vlanId": 3902, "securityZone": "DataCentre"})
    assert r.status_code == 200, r.text
    v = r.json()
    assert v["description"] == "changed" and v["vlanId"] == 3902 and v["aliases"] == ["LT_THREE", "LT_TWO"] and v["securityZone"] == "DataCentre"
    assert api.get("/vlans/LT_TWO").json()["vlanKey"] == key  # alias resolves
    assert api.get(f"/vlans/{key}/usage").json()["inUse"] is False
    r = api.delete(f"/vlans/{key}")
    assert r.status_code == 200 and r.json()["deleted"] == key
    assert api.get(f"/vlans/{key}").status_code == 404


def test_vlan_in_use_cannot_be_deleted_or_renumbered_but_can_be_deprecated(api):
    usage = api.get("/vlans/DCS-SERVERS/usage").json()
    assert usage["inUse"] and any(t["template"].startswith("EXAMPLE-NET-10") for t in usage["templates"]) and "WDC" in usage["hostPools"]
    r = api.delete("/vlans/DCS-SERVERS")
    assert r.status_code == 409 and r.json()["code"] == "IPAM-VLAN-IN-USE" and r.json()["usage"]["templates"]
    # X9 carries it (Workflow 2), so the ID is frozen
    r = api.patch("/vlans/DCS-SERVERS", json={"vlanId": 2999})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-VLAN-IN-USE" and "X9" in r.json()["sites"]
    # description and status are fine
    assert api.patch("/vlans/DCS-SERVERS", json={"description": "Primary server VLAN, DCS (OT) domain"}).status_code == 200


def test_vlan_name_must_stay_unique(api, tag):
    key = f"LT-{tag}-DUP"
    api.post("/vlans", json={"vlanKey": key, "vlanName": f"lt-{tag}-dup"}).raise_for_status()
    r = api.patch(f"/vlans/{key}", json={"vlanName": "v3001-SERVERS"})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-VLAN-DUPLICATE"


# ------------------------------------------------------------------ host pools

def test_host_pool_add_change_members_delete(api, tag):
    code = f"LT-{tag}"
    r = api.post("/host-roles", json={"roleCode": code, "name": "Jump hosts", "vlanKeys": ["CORP-SERVERS"],
                                      "members": [{"name": "jmp01", "hostPosition": "71"}, {"name": "JMP02", "hostPosition": "0.72"}]})
    assert r.status_code == 201, r.text
    assert [m["name"] for m in r.json()["members"]] == ["JMP01", "JMP02"]
    r = api.patch(f"/host-roles/{code}", json={"name": "Jump servers", "vlanKeys": ["CORP-SERVERS", "DCS-SERVERS"]})
    assert r.status_code == 200 and r.json()["vlanKeys"] == ["CORP-SERVERS", "DCS-SERVERS"]
    r = api.put(f"/host-roles/{code}/members", json=[
        {"name": "JMP01", "kind": "fixed", "hostPosition": "71", "secondaryHostOctet": 171},
        {"name": "JMP-SPARE", "kind": "reserved", "rangeStart": 73, "rangeEnd": 75},
    ])
    assert r.status_code == 200, r.text
    assert r.json()["members"][0]["secondaryHostOctet"] == 171 and r.json()["members"][1]["kind"] == "reserved"
    assert api.delete(f"/host-roles/{code}").json()["deleted"] == code


def test_host_pool_collision_is_refused(api, tag):
    # WDC01 already holds .61 on CORP-SERVERS
    r = api.post("/host-roles", json={"roleCode": f"LT-{tag}-X", "vlanKeys": ["CORP-SERVERS"], "members": [{"name": "CLASH01", "hostPosition": "61"}]})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-HOST-COLLISION"
    assert any("WDC" in c for c in r.json()["collisions"])
    # a range over the SQL instances clashes too
    r = api.post("/host-roles", json={"roleCode": f"LT-{tag}-Y", "vlanKeys": ["CORP-SERVERS"], "members": [{"name": "R", "kind": "range", "rangeStart": 110, "rangeEnd": 115}]})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-HOST-COLLISION"


def test_change_that_breaks_a_released_template_is_refused(api, tag):
    # NVR01 at 1.10 on the /22 is fine; 4.10 doesn't fit a /22, so EXAMPLE-NET-10 could no longer deploy
    r = api.put("/host-roles/NVR/members", json=[{"name": "NVR01", "hostPosition": "4.10"}])
    assert r.status_code == 409 and r.json()["code"] == "IPAM-RELEASED-TEMPLATE-CONFLICT"
    assert api.get("/host-roles").json()  # unchanged
    nvr = next(p for p in api.get("/host-roles").json() if p["roleCode"] == "NVR")
    assert nvr["members"][0]["hostPosition"] == "1.10"


def test_host_pool_with_addresses_at_sites_cannot_be_deleted(api):
    r = api.delete("/host-roles/WDC")
    assert r.status_code == 409 and r.json()["code"] == "IPAM-HOSTROLE-IN-USE" and "X9" in r.json()["sites"]


def test_bad_member_definitions(api, tag):
    bad = [
        ([{"name": "A", "hostPosition": "0.300"}], "IPAM-HOST-POSITION-INVALID"),
        ([{"name": "A", "kind": "range", "rangeStart": 20, "rangeEnd": 10}], "IPAM-RANGE-INVALID"),
        ([{"name": "A", "hostPosition": "10"}, {"name": "a", "hostPosition": "11"}], "IPAM-MEMBER-DUPLICATE"),
    ]
    for members, code in bad:
        r = api.post("/host-roles", json={"roleCode": f"LT-{tag}-B", "vlanKeys": [], "members": members})
        assert r.json()["code"] == code, r.text


# ------------------------------------------------------------------ VRFs and address pools

def test_vrf_and_pool_lifecycle(admin, tag):
    api = admin
    vrf, root, child = f"LT-{tag}-VRF", f"LT-{tag}-ROOT", f"LT-{tag}-SITES"
    assert api.post("/vrfs", json={"vrfKey": vrf, "description": "test"}).status_code == 201
    assert api.patch(f"/vrfs/{vrf}", json={"description": "changed"}).json()["description"] == "changed"

    r = api.post("/pools", json={"poolKey": root, "vrf": vrf, "prefixes": ["192.168.0.0/16"]})
    assert r.status_code == 201, r.text
    r = api.post("/pools", json={"poolKey": child, "parentPool": root, "vrf": vrf, "allocationPrefixLength": 24,
                                 "prefixes": ["192.168.0.0/17"], "exclusions": ["192.168.0.0/24"]})
    assert r.status_code == 201, r.text
    assert r.json()["exclusions"] == ["192.168.0.0/24"]

    # prefix rules: inside the parent, private unless confirmed, no host bits
    assert api.post(f"/pools/{child}/prefixes", json={"cidr": "10.0.0.0/8"}).json()["code"] == "IPAM-PREFIX-OUTSIDE-PARENT"
    assert api.post(f"/pools/{root}/prefixes", json={"cidr": "203.0.113.0/24"}).json()["code"] == "IPAM-PREFIX-NOT-PRIVATE"
    assert api.post(f"/pools/{root}/prefixes", json={"cidr": "203.0.113.0/24", "confirmNonPrivate": True}).status_code == 201
    assert api.post(f"/pools/{root}/prefixes", json={"cidr": "10.1.1.1/16"}).json()["code"] == "IPAM-CIDR-INVALID"

    r = api.post(f"/pools/{child}/exclusions", json={"cidr": "192.168.1.0/24"})
    assert r.status_code == 201 and "192.168.1.0/24" in r.json()["exclusions"]
    r = api.delete(f"/pools/{child}/exclusions", params={"cidr": "192.168.1.0/24"})
    assert r.status_code == 200 and "192.168.1.0/24" not in r.json()["exclusions"]
    assert api.patch(f"/pools/{child}", json={"description": "Test sites", "allocationPrefixLength": 25}).json()["allocationPrefixLength"] == 25

    # the parent prefix feeding a child can't go; nor can a VRF or pool still in use
    assert api.delete(f"/pools/{root}/prefixes", params={"cidr": "192.168.0.0/16"}).json()["code"] == "IPAM-PREFIX-IN-USE"
    assert api.delete(f"/pools/{root}").json()["code"] == "IPAM-POOL-IN-USE"
    assert api.delete(f"/vrfs/{vrf}").json()["code"] == "IPAM-VRF-IN-USE"

    assert api.delete(f"/pools/{child}").json()["deleted"] == child
    assert api.delete(f"/pools/{root}/prefixes", params={"cidr": "203.0.113.0/24"}).status_code == 200
    assert api.delete(f"/pools/{root}").json()["deleted"] == root
    assert api.delete(f"/vrfs/{vrf}").json()["deleted"] == vrf


def test_keys_cannot_change_pools(api):
    r = api.post("/vrfs", json={"vrfKey": "LT-NOPE"})
    assert r.status_code == 403 and r.json()["code"] == "IPAM-PERMISSION-DENIED"


def test_pool_with_allocations_is_protected(admin):
    api = admin
    site_pool = next(p for p in api.get("/pools").json() if p["poolKey"] == "SITE-POOL-AU")
    assert site_pool["blocksAllocated"] >= 1
    assert api.delete("/pools/SITE-POOL-AU").json()["code"] == "IPAM-POOL-IN-USE"
    assert api.patch("/pools/SITE-POOL-AU", json={"allocationPrefixLength": 17}).json()["code"] == "IPAM-POOL-IN-USE"
    assert api.delete("/pools/ENTERPRISE/prefixes", params={"cidr": "10.0.0.0/8"}).json()["code"] == "IPAM-PREFIX-IN-USE"
    block = next(s for s in api.get("/sites").json() if s["siteCode"] == "X9")["blocks"][0]["cidr"]
    r = api.post("/pools/SITE-POOL-AU/exclusions", json={"cidr": block})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-EXCLUSION-ALLOCATED"


def test_library_changes_are_audited(api, tag):
    key = f"LT-{tag}-AUD"
    api.post("/vlans", json={"vlanKey": key, "vlanName": f"lt-{tag}-aud"}).raise_for_status()
    r = api.patch(f"/vlans/{key}", json={"description": "audited"})
    e = api.get("/audit", params={"requestId": r.headers["X-Request-Id"]}).json()[0]
    assert e["action"] == "vlan.update" and e["objectKey"] == key
    assert e["changes"]["after"]["description"] == "audited"
