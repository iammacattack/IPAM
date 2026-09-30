"""Template layout: sections, split/merge, bindings (spec §5.5, §6.1, §17.1)."""

from __future__ import annotations

import copy
from ipaddress import IPv4Network

import pytest

from nextdc_ipam_engine import (
    EngineError,
    EngineValidationError,
    check_base,
    content_hash,
    expand_vlan_rules,
    layout_from_content,
    relocate,
)


def codes(exc: EngineValidationError) -> set[str]:
    return {e.code for e in exc.errors}


def test_example_net_10_reconciles_to_265(example_net_10):
    layout = layout_from_content(example_net_10)
    summary = layout.summary()
    by_section = {s["sectionKey"]: s for s in summary["sections"]}
    assert by_section["CORP"]["subnets"] == 24
    assert by_section["CORP"]["bySize"] == {"/25": 24}
    assert by_section["DCS"]["units"] == 244
    assert by_section["DCS"]["subnets"] == 241
    assert by_section["DCS"]["bySize"] == {"/24": 240, "/22": 1}
    assert summary["subnetCount"] == 265


def test_example_net_10_no_gaps_or_overlaps(example_net_10):
    layout = layout_from_content(example_net_10)
    nets = sorted((s.relative for s in layout.subnets), key=lambda n: int(n.network_address))
    for a, b in zip(nets, nets[1:]):
        assert int(a.broadcast_address) + 1 == int(b.network_address), f"gap or overlap between {a} and {b}"
    assert nets[0] == IPv4Network("0.0.0.0/25")
    assert int(nets[-1].broadcast_address) == 0xFFFF


def test_example_net_10_240_unit_extent_gives_261(example_net_10):
    t = copy.deepcopy(example_net_10)
    t["blocks"][0]["sections"][1]["extent"] = {"start": "auto", "units": 240}
    layout = layout_from_content(t)
    assert layout.summary()["subnetCount"] == 261


def test_vlan_rule_binds_every_subnet(example_net_10):
    layout = layout_from_content(example_net_10)
    expanded, vlans = expand_vlan_rules(example_net_10, layout)
    layout2 = layout_from_content(expanded)
    assert all(s.vlan_key for s in layout2.subnets)
    # 265 subnets minus the 3 explicit bindings
    assert len(vlans) == 262
    ids = [v["vlanId"] for v in vlans] + [3001, 2013, 2080]
    assert len(ids) == len(set(ids)), "VLAN IDs must be unique within the template"
    names = [v["vlanName"] for v in vlans]
    assert len(names) == len(set(names))
    # Re-expanding is a no-op, so saving a draft twice doesn't change it.
    again, more = expand_vlan_rules(expanded, layout2)
    assert more == [] and again == expanded


def test_explicit_bindings_survive_rule(example_net_10):
    layout = layout_from_content(expand_vlan_rules(example_net_10, layout_from_content(example_net_10))[0])
    bound = {s.vlan_key: str(s.relative) for s in layout.subnets}
    assert bound["CORP-SERVERS"] == "0.0.1.0/25"
    assert bound["DCS-SERVERS"] == "0.0.13.0/24"
    assert bound["DCS-SECURITY"] == "0.0.80.0/22"


def test_misaligned_merge_rejected_with_suggestion(example_net_10):
    t = copy.deepcopy(example_net_10)
    t["blocks"][0]["sections"][1]["subnetOverrides"] = [{"relativeCidr": "0.0.81.0/22", "mergeFrom": 24}]
    t["blocks"][0]["sections"][1]["vlanBindings"] = []
    with pytest.raises(EngineValidationError) as exc:
        layout_from_content(t)
    err = next(e for e in exc.value.errors if e.code == "IPAM-MERGE-MISALIGNED")
    assert err.detail["suggested"] == "0.0.80.0/22"


def test_merge_over_bound_subnet_is_orphaned(example_net_10):
    t = copy.deepcopy(example_net_10)
    dcs = t["blocks"][0]["sections"][1]
    dcs["vlanBindings"].append({"relativeCidr": "0.0.81.0/24", "vlanKey": "SOMETHING"})
    with pytest.raises(EngineValidationError) as exc:
        layout_from_content(t)
    assert "IPAM-BINDING-ORPHANED" in codes(exc.value)


def test_override_cannot_cross_section(example_net_10):
    t = copy.deepcopy(example_net_10)
    # 0.0.8.0/21 covers CORP 8-11 and DCS 12-15
    t["blocks"][0]["sections"][1]["subnetOverrides"].append({"relativeCidr": "0.0.8.0/21", "mergeFrom": 24})
    with pytest.raises(EngineValidationError) as exc:
        layout_from_content(t)
    assert "IPAM-OVERRIDE-OUTSIDE-SECTION" in codes(exc.value)


def test_extent_overlap_and_overrun():
    base = {
        "blocks": [
            {
                "blockKey": "SITE",
                "prefixLength": 16,
                "vrf": "NXT",
                "unitPrefix": 24,
                "sections": [
                    {"sectionKey": "A", "vrf": "CORP", "extent": {"start": "0.0.0.0", "units": 20}},
                    {"sectionKey": "B", "vrf": "DCS", "extent": {"start": "0.0.10.0", "units": 5}},
                ],
            }
        ]
    }
    with pytest.raises(EngineValidationError) as exc:
        layout_from_content(base)
    assert "IPAM-EXTENT-OVERLAP" in codes(exc.value)

    base["blocks"][0]["sections"] = [{"sectionKey": "A", "vrf": "CORP", "extent": {"units": 300}}]
    with pytest.raises(EngineValidationError) as exc:
        layout_from_content(base)
    assert "IPAM-EXTENT-OVERRUN" in codes(exc.value)


def test_remaining_stops_at_pinned_section_and_upto():
    t = {
        "blocks": [
            {
                "blockKey": "SITE",
                "prefixLength": 16,
                "vrf": "NXT",
                "unitPrefix": 24,
                "sections": [
                    {"sectionKey": "CORP", "vrf": "CORP", "extent": {"units": 12}},
                    {"sectionKey": "DCS", "vrf": "DCS", "extent": {"units": "remaining"}},
                    {"sectionKey": "CSMS", "vrf": "DCS", "extent": {"start": "0.0.64.0", "units": {"upTo": 500}}},
                ],
            }
        ]
    }
    s = {x["sectionKey"]: x for x in layout_from_content(t).summary()["sections"]}
    assert s["DCS"]["units"] == 52 and s["DCS"]["start"] == "0.0.12.0"
    assert s["CSMS"]["units"] == 192 and s["CSMS"]["start"] == "0.0.64.0"


def test_content_hash_is_stable_and_order_independent(example_net_10):
    a = content_hash(example_net_10)
    b = content_hash(copy.deepcopy(example_net_10))
    assert a == b and a.startswith("sha256:")
    reordered = dict(reversed(list(example_net_10.items())))
    assert content_hash(reordered) == a


def test_relocate_and_base_checks():
    assert relocate(IPv4Network("0.0.13.0/24"), IPv4Network("10.9.0.0/16")) == IPv4Network("10.9.13.0/24")
    assert check_base("10.9.0.0", 16) == IPv4Network("10.9.0.0/16")
    with pytest.raises(EngineError) as exc:
        check_base("10.9.45.0", 16)
    assert exc.value.code == "IPAM-BASEIP-MISALIGNED"
    assert exc.value.detail["suggested"] == "10.9.0.0/16"
