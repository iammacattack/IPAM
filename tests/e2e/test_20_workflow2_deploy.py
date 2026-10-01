"""Workflow 2 (spec §17.2): the Site Delivery Wizard deploys site X9 with no base IP."""

from __future__ import annotations

import uuid

import pytest

from helpers import API_KEY, make_client

SDW = "SiteDeliveryWizard/2.4"


@pytest.fixture(scope="module")
def sdw():
    with make_client(SDW, API_KEY) as c:
        yield c


@pytest.fixture(scope="module")
def x9(sdw):
    """Steps 1-3: list released templates, preview, then Go (reserve)."""
    templates = sdw.get("/templates", params={"state": "RELEASED"}).json()
    assert "EXAMPLE-NET-10" in {t["templateKey"] for t in templates}
    assert all(v["state"] == "RELEASED" for t in templates for v in t["versions"])

    preview = sdw.get("/templates/EXAMPLE-NET-10/preview", params={"pool": "SITE-POOL-AU"}).json()
    assert preview["persisted"] is False and preview["blocks"][0]["nonBinding"] is True

    key = str(uuid.uuid4())
    r = sdw.post(
        "/sites",
        json={"siteCode": "X9", "countryCode": "AU", "templateKey": "EXAMPLE-NET-10"},
        headers={"Idempotency-Key": key},
    )
    assert r.status_code == 201, r.text
    return {"idem": key, "body": r.json()}


def test_reserve_returns_the_whole_design(x9):
    site = x9["body"]
    assert site["status"] == "reserved" and site["allocationState"] == "reserved"
    assert site["reservation"]["reservationId"] and site["reservation"]["expiresAt"]
    assert site["subnetCount"] == 265
    assert site["template"]["key"] == "EXAMPLE-NET-10" and site["template"]["contentHash"].startswith("sha256:")
    block = site["blocks"][0]["cidr"]
    assert block.endswith("/16")
    # gateways and fixed host-pool members are held as reserved
    dcs_servers = next(n for n in site["networks"] if n["vlanKey"] == "DCS-SERVERS")
    assert dcs_servers["gateway"].endswith(".13.1")
    assert {h["member"] for h in dcs_servers["hosts"]} >= {"WDC01", "WDC02"}
    assert all(h["status"] == "reserved-pattern" for h in dcs_servers["hosts"])


def test_x9_auto_registered_unverified(api, x9):
    assert x9["body"]["siteCodeStatus"] == "unverified"
    codes = {c["code"]: c for c in api.get("/site-codes", params={"status": "unverified"}).json()}
    assert "X9" in codes


def test_go_twice_with_same_key_is_idempotent(sdw, x9):
    r = sdw.post(
        "/sites",
        json={"siteCode": "X9", "countryCode": "AU", "templateKey": "EXAMPLE-NET-10"},
        headers={"Idempotency-Key": x9["idem"]},
    )
    assert r.status_code == 200 and r.headers.get("Idempotent-Replay") == "true"
    assert r.json()["siteId"] == x9["body"]["siteId"]
    assert r.json()["blocks"] == x9["body"]["blocks"]


def test_different_request_for_live_code_is_refused(sdw, x9):
    r = sdw.post("/sites", json={"siteCode": "X9", "templateKey": "EXAMPLE-NET-10"})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-SITE-CODE-IN-USE"


def test_reserved_block_cannot_be_taken(sdw, x9):
    block = x9["body"]["blocks"][0]["cidr"]
    r = sdw.post("/sites", json={"siteCode": "X8", "templateKey": "EXAMPLE-NET-10", "baseIp": block.split("/")[0]})
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["code"] == "IPAM-OVERLAP" and body["heldBySite"] == "X9"


def test_misaligned_base_ip_is_rejected_not_corrected(sdw):
    r = sdw.post("/sites", json={"siteCode": "X7", "templateKey": "EXAMPLE-NET-10", "baseIp": "10.199.45.0"})
    assert r.status_code == 422
    assert r.json()["code"] == "IPAM-BASEIP-MISALIGNED" and r.json()["suggested"] == "10.199.0.0/16"


def test_confirm_makes_it_permanent(sdw, x9):
    site = x9["body"]
    r = sdw.post("/sites/X9:confirm", json={"reservationId": "00000000-0000-0000-0000-000000000000"})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-RESERVATION-MISMATCH"
    r = sdw.post("/sites/X9:confirm", json={"reservationId": site["reservation"]["reservationId"]})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "allocated" and r.json()["allocationState"] == "confirmed"
    assert "reservation" not in r.json()
    # a confirmed site can't be released (retire is a later phase)
    assert sdw.post("/sites/X9:release").json()["code"] == "IPAM-SITE-STATE"
    # and API keys can never retire (delete) a site - that needs an Administrator with 2FA (spec §10.4, Q8)
    r = sdw.post("/sites/X9:retire", json={"reason": "test"})
    assert r.status_code == 403 and r.json()["code"] == "IPAM-PERMISSION-DENIED"


def test_release_returns_space_immediately(sdw):
    r = sdw.post("/sites", json={"siteCode": "X8", "templateKey": "EXAMPLE-NET-10"})
    assert r.status_code == 201, r.text
    block = r.json()["blocks"][0]["cidr"]
    assert sdw.post("/sites/X8:release").json()["status"] == "released"
    r = sdw.post("/sites", json={"siteCode": "X7", "templateKey": "EXAMPLE-NET-10", "baseIp": block})
    assert r.status_code == 201, r.text
    sdw.post("/sites/X7:release").raise_for_status()


def test_expiry_returns_space(sdw, db):
    r = sdw.post("/sites", json={"siteCode": "X6", "templateKey": "EXAMPLE-NET-10"})
    assert r.status_code == 201
    block = r.json()["blocks"][0]["cidr"]
    db.execute("UPDATE site SET expires_at = now() - interval '1 second' WHERE site_code = 'X6' AND status = 'reserved'")
    site = sdw.get("/sites/X6").json()  # reads sweep lapsed reservations
    assert site["status"] == "expired" and site["blocks"] == []
    r = sdw.post("/sites", json={"siteCode": "X5", "templateKey": "EXAMPLE-NET-10", "baseIp": block})
    assert r.status_code == 201
    sdw.post("/sites/X5:release").raise_for_status()


def test_audit_trail_for_x9(api, x9):
    events = api.get("/audit", params={"siteCode": "X9", "limit": 200}).json()
    actions = [e["action"] for e in events]
    assert "site.reserve" in actions and "site.confirm" in actions
    reserve = next(e for e in events if e["action"] == "site.reserve" and e["outcome"] == "success")
    assert reserve["clientName"] == SDW
    assert reserve["actorType"] == "api-key" and reserve["sourceIp"]
    assert reserve["changes"]["after"]["blocks"][0]["cidr"] == x9["body"]["blocks"][0]["cidr"]
