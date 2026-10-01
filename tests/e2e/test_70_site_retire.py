"""Deleting sites: retire (code freed, space quarantined), purge, and the guards (spec §5.7, FR-14)."""

from __future__ import annotations

import psycopg
import pytest

from helpers import API_KEY, DATABASE_URL, make_client
from test_50_users_2fa import browser, enrol, make_user, sign_in


@pytest.fixture(scope="module")
def key():
    with make_client("pytest/retire", API_KEY) as c:
        yield c


@pytest.fixture(scope="module")
def admin():
    user = make_user(["admin"])
    with browser() as c:
        sign_in(c, user)
        enrol(c)  # also opens the step-up window
        yield c
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute("DELETE FROM app_user WHERE username = %s", (user,))


def deploy(key, code: str) -> dict:
    r = key.post("/sites", json={"siteCode": code, "templateKey": "EXAMPLE-NET-10"})
    assert r.status_code == 201, r.text
    key.post(f"/sites/{code}:confirm", json={"reservationId": r.json()["reservation"]["reservationId"]}).raise_for_status()
    return r.json()


def test_retire_quarantine_and_purge(key, admin):
    site = deploy(key, "RT1")
    block = site["blocks"][0]["cidr"]
    key.get("/lookup/host-ip", params={"site": "RT1", "vlan": "VLAN_OT_SERVER", "host": "WDC01", "resolve": "assign", "hostname": "AURT1WDC01"}).raise_for_status()

    # a reason is required, and assigned hosts block it unless forced
    assert admin.post("/sites/RT1:retire", json={"reason": ""}).json()["code"] == "IPAM-REASON-REQUIRED"
    r = admin.post("/sites/RT1:retire", json={"reason": "Decommissioned"})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-SITE-HAS-ASSIGNMENTS" and "AURT1WDC01" in r.json()["assignments"][0]
    r = admin.post("/sites/RT1:retire", json={"reason": "Decommissioned", "changeRef": "CHG001", "force": True})
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["status"] == "retired" and s["retirement"]["reason"] == "Decommissioned" and s["retirement"]["quarantineUntil"]

    # the code is free again, but the space is still held (quarantine)
    assert key.get("/lookup/host-ip", params={"site": "RT1", "vlan": "VLAN_OT_SERVER", "host": "WDC01"}).status_code == 404
    r = key.post("/sites", json={"siteCode": "RT2", "templateKey": "EXAMPLE-NET-10", "baseIp": block, "reservationDays": 1})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-OVERLAP" and r.json()["heldBySite"] == "RT1"

    # purging inside the quarantine needs releaseNow + a reason
    r = admin.post("/sites/RT1:purge", json={})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-SITE-QUARANTINED"
    assert admin.post("/sites/RT1:purge", json={"releaseNow": True}).json()["code"] == "IPAM-REASON-REQUIRED"
    r = admin.post("/sites/RT1:purge", json={"releaseNow": True, "reason": "Test site"})
    assert r.status_code == 200 and r.json()["blocksReleased"] == [block]

    # the space is free and the record is gone; the audit trail stays
    r = key.post("/sites", json={"siteCode": "RT2", "templateKey": "EXAMPLE-NET-10", "baseIp": block})
    assert r.status_code == 201, r.text
    key.post("/sites/RT2:release").raise_for_status()
    assert key.get("/sites/RT1").status_code == 404
    actions = [e["action"] for e in key.get("/audit", params={"siteCode": "RT1", "limit": 100}).json()]
    assert "site.retire" in actions and "site.purge" in actions


def test_quarantine_ends_on_its_own(key, admin):
    site = deploy(key, "RT3")
    block = site["blocks"][0]["cidr"]
    admin.post("/sites/RT3:retire", json={"reason": "Closed"}).raise_for_status()
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute("UPDATE site SET quarantine_until = now() - interval '1 second' WHERE site_code = 'RT3' AND status = 'retired'")
    s = key.get("/sites/RT3").json()  # reads sweep ended quarantines
    assert s["status"] == "retired" and s["blocks"] == [] and s["retirement"]["spaceReleasedAt"]
    r = key.post("/sites", json={"siteCode": "RT4", "templateKey": "EXAMPLE-NET-10", "baseIp": block})
    assert r.status_code == 201
    key.post("/sites/RT4:release").raise_for_status()
    # after the quarantine, purge needs no override
    assert admin.post("/sites/RT3:purge", json={}).status_code == 200


def test_retire_rules(key, admin):
    r = key.post("/sites", json={"siteCode": "RT5", "templateKey": "EXAMPLE-NET-10"})
    assert admin.post("/sites/RT5:retire", json={"reason": "x-y-z"}).json()["code"] == "IPAM-SITE-STATE"  # reserved: release instead
    key.post("/sites/RT5:release").raise_for_status()
    # the spec's DELETE form works too
    deploy(key, "RT6")
    r = admin.request("DELETE", "/sites/RT6", params={"reason": "Spec form"})
    assert r.status_code == 200 and r.json()["status"] == "retired"
    r = admin.request("DELETE", "/sites/RT6", params={"purge": "true", "releaseNow": "true", "reason": "cleanup"})
    assert r.status_code == 200
