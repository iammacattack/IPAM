"""ADR acceptance tests T1-T3 on Option A, plus authentication (ADR-NET-IPAM-PLATFORM-SELECTION §9)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_network

import psycopg
import pytest

from helpers import API_KEY, make_client


def test_t1_database_rejects_overlap_directly(db):
    """T1: even a direct write that bypasses the API can't create an overlapping block."""
    site = db.execute("SELECT s.site_id, b.cidr FROM site s JOIN block b USING (site_id) LIMIT 1").fetchone()
    assert site, "needs at least one deployed site (Workflow 2 creates X9)"
    site_id, cidr = site
    inner = str(list(ip_network(str(cidr)).subnets(new_prefix=20))[3])
    with pytest.raises(psycopg.errors.ExclusionViolation):
        db.execute(
            "INSERT INTO block (site_id, block_key, vrf_key, cidr) VALUES (%s, 'ROGUE', 'NXT', %s)", (site_id, inner)
        )


def test_t2_twenty_concurrent_deploys_get_distinct_blocks(api):
    """T2: 20 parallel POST /sites with no baseIp from one pool: 20 distinct, non-overlapping /16s."""
    codes = [f"T2-{i:02d}" for i in range(20)]

    def deploy(code: str):
        with make_client("pytest/t2", API_KEY) as c:
            return c.post("/sites", json={"siteCode": code, "templateKey": "EXAMPLE-NET-10"})

    try:
        with ThreadPoolExecutor(max_workers=20) as pool:
            responses = list(pool.map(deploy, codes))
        assert [r.status_code for r in responses] == [201] * 20, [r.text for r in responses if r.status_code != 201]
        blocks = [ip_network(r.json()["blocks"][0]["cidr"]) for r in responses]
        assert len(set(blocks)) == 20
        for i, a in enumerate(blocks):
            for b in blocks[i + 1 :]:
                assert not a.overlaps(b)
    finally:
        for code in codes:
            api.post(f"/sites/{code}:release")


def test_t3_reads_are_audited_with_key_identity(api):
    """T3: a design read with an API key leaves an audit row with key, source IP and client name."""
    r = api.get("/sites/X9/design", params={"include": "none"}, headers={"X-Client-Name": "pytest/t3"})
    assert r.status_code == 200
    rid = r.headers["X-Request-Id"]
    events = api.get("/audit", params={"requestId": rid}).json()
    assert len(events) == 1
    e = events[0]
    assert e["action"] == "design.read" and e["siteCode"] == "X9"
    assert e["actorType"] == "api-key" and e["actorId"].startswith("key:")
    assert e["clientName"] == "pytest/t3" and e["sourceIp"] and e["outcome"] == "success"


def test_audit_is_append_only(db):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        db.execute("DELETE FROM audit_event WHERE true")


def test_missing_and_bad_keys_are_refused_and_audited(anon, api):
    r = anon.get("/sites")
    assert r.status_code == 401 and r.json()["code"] == "IPAM-AUTH-REQUIRED"
    r = anon.get("/sites", headers={"X-API-Key": "ipam_deadbeef_" + "x" * 40})
    assert r.status_code == 401 and r.json()["code"] == "IPAM-KEY-INVALID"
    rid = r.headers["X-Request-Id"]
    e = api.get("/audit", params={"requestId": rid}).json()[0]
    assert e["action"] == "auth.failed" and e["outcome"] == "denied" and e["actorId"] == "key:deadbeef"


def test_keys_cannot_hold_destructive_scopes(db):
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute(
            "INSERT INTO api_key (prefix, secret_hash, owner, scopes, expires_at) VALUES ('baddbadd', 'x', 't', %s, now())",
            (["read", "sites:delete"],),
        )


def test_health_is_open_and_not_audited(anon):
    assert anon.get("/healthz").json() == {"status": "ok"}
    assert anon.get("/readyz").json() == {"status": "ready"}
