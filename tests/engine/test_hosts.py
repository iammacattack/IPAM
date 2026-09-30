"""Host addressing worked examples (spec §5.6 table, §17.3a pass criteria)."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

import pytest

from nextdc_ipam_engine import (
    EngineError,
    HostPool,
    HostPosition,
    expand_vlan_rules,
    layout_from_content,
    placement_matrix,
    resolve_host,
)


def gw(net: str) -> IPv4Address:
    return IPv4Network(net).network_address + 1


@pytest.mark.parametrize(
    "subnet, position, expected, used",
    [
        ("10.9.1.0/24", "0.61", "10.9.1.61", "primary"),
        ("10.9.1.0/25", "0.61", "10.9.1.61", "primary"),
        ("10.9.1.128/25", "0.61", "10.9.1.189", "calculated"),
        ("10.9.2.64/26", "0.61", "10.9.2.125", "calculated"),
        ("10.9.80.0/22", "0.61", "10.9.80.61", "primary"),
        ("10.9.80.0/22", "1.10", "10.9.81.10", "primary"),
    ],
)
def test_spec_worked_examples(subnet, position, expected, used):
    r = resolve_host(IPv4Network(subnet), HostPosition.parse(position), gateway=gw(subnet))
    assert str(r.ip) == expected
    assert r.octet_used == used


def test_no_usable_candidate_is_a_conflict():
    # 0.63 on 10.9.2.64/26: literal .63 is outside, calculated .127 is broadcast
    with pytest.raises(EngineError) as exc:
        resolve_host(IPv4Network("10.9.2.64/26"), HostPosition.parse("0.63"), gateway=gw("10.9.2.64/26"))
    assert exc.value.code == "IPAM-HOST-OCTET-CONFLICT"
    reasons = [c["reason"] for c in exc.value.detail["candidates"]]
    assert reasons == ["outside-subnet", "broadcast-address"]


def test_explicit_secondary_wins_over_calculated():
    r = resolve_host(
        IPv4Network("10.9.1.128/25"), HostPosition.parse("0.61"), secondary_octet=161, gateway=gw("10.9.1.128/25")
    )
    assert str(r.ip) == "10.9.1.161" and r.octet_used == "secondary"


def test_gateway_is_never_a_host():
    # literal .1 is the gateway and the calculated position is also .1, so it's a conflict
    with pytest.raises(EngineError) as exc:
        resolve_host(IPv4Network("10.9.1.0/24"), HostPosition.parse("0.1"), gateway=gw("10.9.1.0/24"))
    assert exc.value.detail["candidates"][0]["reason"] == "gateway"


def test_zero_and_255_avoided_in_supernets():
    with pytest.raises(EngineError):
        resolve_host(IPv4Network("10.9.80.0/22"), HostPosition.parse("1.0"), gateway=gw("10.9.80.0/22"))
    r = resolve_host(
        IPv4Network("10.9.80.0/22"),
        HostPosition.parse("1.0"),
        gateway=gw("10.9.80.0/22"),
        avoid_zero_and_broadcast_in_supernets=False,
    )
    assert str(r.ip) == "10.9.81.0"


@pytest.mark.parametrize("subnet, position", [("10.9.80.0/22", "4.10"), ("10.9.1.0/24", "1.10")])
def test_index_outside_span_is_a_configuration_error(subnet, position):
    # spec §5.6: "An index beyond the supernet's span ... is a configuration error"; on a /24 the index is always 0
    with pytest.raises(EngineError) as exc:
        resolve_host(IPv4Network(subnet), HostPosition.parse(position), gateway=gw(subnet))
    assert exc.value.code == "IPAM-HOST-POSITION-INVALID"


def test_position_parsing():
    assert HostPosition.parse("61") == HostPosition(0, 61)
    assert HostPosition.parse(61) == HostPosition(0, 61)
    assert str(HostPosition.parse("1.10")) == "1.10"
    with pytest.raises(EngineError):
        HostPosition.parse("0.300")


def test_placement_matrix_for_example_net_10(example_net_10, host_roles):
    layout = layout_from_content(expand_vlan_rules(example_net_10, layout_from_content(example_net_10))[0])
    matrix = placement_matrix(layout, [HostPool.from_dict(p) for p in host_roles])
    assert not [p for p in matrix if p.conflict], [p.to_dict() for p in matrix if p.conflict]
    got = {(p.member, p.vlan_key): str(p.ip) for p in matrix}
    assert got[("WDC01", "DCS-SERVERS")] == "0.0.13.61"
    assert got[("WDC02", "DCS-SERVERS")] == "0.0.13.62"
    assert got[("WDC01", "CORP-SERVERS")] == "0.0.1.61"
    assert got[("NVR01", "DCS-SECURITY")] == "0.0.81.10"
    supernet = next(p for p in matrix if p.member == "NVR01")
    assert supernet.warnings, "fixed host on a supernet should warn"


def test_collision_is_reported():
    layout = layout_from_content(
        {
            "blocks": [
                {
                    "blockKey": "SITE",
                    "prefixLength": 16,
                    "vrf": "NXT",
                    "sections": [
                        {
                            "sectionKey": "CORP",
                            "vrf": "CORP",
                            "extent": {"units": 2},
                            "vlanBindings": [{"relativeCidr": "0.0.1.0/24", "vlanKey": "X"}],
                        }
                    ],
                }
            ]
        }
    )
    pools = [
        HostPool.from_dict({"roleCode": "A", "vlanKeys": ["X"], "members": [{"name": "A1", "hostPosition": "61"}]}),
        HostPool.from_dict({"roleCode": "B", "vlanKeys": ["X"], "members": [{"name": "B1", "hostPosition": "61"}]}),
    ]
    matrix = placement_matrix(layout, pools)
    assert all(p.conflict and p.conflict["code"] == "IPAM-HOST-COLLISION" for p in matrix)
