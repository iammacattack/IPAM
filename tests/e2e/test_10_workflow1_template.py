"""Workflow 1 (spec §17.1): a Network Architect builds template EXAMPLE-NET-10 through the API."""

from __future__ import annotations

import copy


def test_build_validate_and_release(api, example_content, unique):
    key = f"WF1-{unique}"

    # Steps 1-7: create the draft (CORP 12 units split to /25, DCS remaining with a /22 merge, bulk VLAN rule)
    r = api.post("/templates", json={"templateKey": key, "description": "Workflow 1 e2e", "content": example_content})
    assert r.status_code == 201, r.text
    v1 = r.json()
    assert v1["state"] == "DRAFT" and v1["version"] == 1
    assert v1["contentHash"].startswith("sha256:")
    sections = {s["sectionKey"]: s for s in v1["summary"]["sections"]}
    assert sections["CORP"]["subnets"] == 24 and sections["CORP"]["bySize"] == {"/25": 24}
    assert sections["DCS"]["units"] == 244 and sections["DCS"]["subnets"] == 241
    assert v1["summary"]["subnetCount"] == 265

    # Step 6: every subnet carries a VLAN binding with a unique ID and name
    bindings = [b for s in v1["content"]["blocks"][0]["sections"] for b in s["vlanBindings"]]
    assert len(bindings) == 265

    report = api.post(f"/templates/{key}/versions/1:validate").json()
    assert report["valid"], report["errors"]
    assert report["placement"]["conflicts"] == 0
    assert any(h["member"] == "NVR01" for h in report["placement"]["highlighted"]), "supernet placement is highlighted"

    # A DRAFT isn't offered to delivery tools
    released = {t["templateKey"] for t in api.get("/templates", params={"state": "RELEASED"}).json()}
    assert key not in released

    # Step 8: release needs notes and evidence
    r = api.post(f"/templates/{key}/versions/1:release", json={})
    assert r.status_code == 422 and r.json()["code"] == "IPAM-RELEASE-NOTES-REQUIRED"
    r = api.post(f"/templates/{key}/versions/1:release", json={"releaseNotes": "e2e", "evidence": "validate report"})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "RELEASED"
    released = {t["templateKey"] for t in api.get("/templates", params={"state": "RELEASED"}).json()}
    assert key in released

    # Frozen once released
    r = api.patch(f"/templates/{key}/versions/1", json={"content": example_content})
    assert r.status_code == 409 and r.json()["code"] == "IPAM-TEMPLATE-FROZEN"


def test_misaligned_merge_is_rejected_with_suggestion(api, example_content, unique):
    bad = copy.deepcopy(example_content)
    dcs = bad["blocks"][0]["sections"][1]
    dcs["subnetOverrides"] = [{"relativeCidr": "0.0.81.0/22", "mergeFrom": 24}]
    dcs["vlanBindings"] = [b for b in dcs["vlanBindings"] if b["vlanKey"] != "DCS-SECURITY"]
    r = api.post("/templates", json={"templateKey": f"WF1-BAD-{unique}", "content": bad})
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "IPAM-MERGE-MISALIGNED"
    assert any(e.get("suggested") == "0.0.80.0/22" for e in body["errors"])


def test_merge_over_a_bound_subnet_is_blocked(api, example_content, unique):
    bad = copy.deepcopy(example_content)
    bad["blocks"][0]["sections"][1]["vlanBindings"].append({"relativeCidr": "0.0.82.0/24", "vlanKey": "DCS-SERVERS"})
    r = api.post("/templates", json={"templateKey": f"WF1-ORPH-{unique}", "content": bad})
    assert r.status_code == 422
    assert "IPAM-BINDING-ORPHANED" in {e["code"] for e in r.json()["errors"]}


def test_new_release_retires_the_unused_previous_version(api, example_content, unique):
    key = f"WF1-LC-{unique}"
    assert api.post("/templates", json={"templateKey": key, "content": example_content}).status_code == 201
    api.post(f"/templates/{key}/versions/1:release", json={"releaseNotes": "v1", "evidence": "e2e"}).raise_for_status()
    r = api.post(f"/templates/{key}/versions", json={})  # copy-on-write from latest
    assert r.status_code == 201 and r.json()["version"] == 2 and r.json()["state"] == "DRAFT"
    api.post(f"/templates/{key}/versions/2:release", json={"releaseNotes": "v2", "evidence": "e2e"}).raise_for_status()
    states = {v["version"]: v["state"] for v in api.get(f"/templates/{key}").json()["versions"]}
    assert states == {1: "RETIRED", 2: "RELEASED"}
