"""VLAN attribute lookup fields (spec §8.2.1, §17.3a)."""

from __future__ import annotations

from ipaddress import IPv4Network

import pytest

from nextdc_ipam_engine import EngineError, network_portion, validate_octet, vlan_attributes


def test_attributes_for_a_24():
    net = IPv4Network("10.9.13.0/24")
    a = vlan_attributes(net, net.network_address + 1)
    assert a == {
        "gateway": "10.9.13.1",
        "mask": "255.255.255.0",
        "prefix": 24,
        "cidr": "10.9.13.0/24",
        "network": "10.9.13.0",
        "networkPortion": "10.9.13",
        "twoOctets": "10.9",
        "spansThirdOctets": "13",
        "broadcast": "10.9.13.255",
        "firstUsable": "10.9.13.1",
        "lastUsable": "10.9.13.254",
    }


@pytest.mark.parametrize("cidr", ["10.9.10.0/25", "10.9.10.128/25"])
def test_3oct_is_mask_independent(cidr):
    assert network_portion(IPv4Network(cidr)) == "10.9.10"


def test_supernet_fields():
    net = IPv4Network("10.9.80.0/22")
    a = vlan_attributes(net, net.network_address + 1)
    assert a["networkPortion"] == "10.9.80"
    assert a["spansThirdOctets"] == "80-83"
    assert network_portion(net, 1) == "10.9.81"
    with pytest.raises(EngineError) as exc:
        network_portion(net, 4)
    assert exc.value.code == "IPAM-INDEX-OUT-OF-RANGE"


def test_validate_octet():
    net = IPv4Network("10.9.1.128/25")
    gw = net.network_address + 1
    assert validate_octet(net, gw, 189)["usable"] is True
    bad = validate_octet(net, gw, 61)
    assert bad["usable"] is False and bad["reason"] == "outside-subnet"
    assert validate_octet(net, gw, 128)["reason"] == "network-address"
    assert validate_octet(net, gw, 129)["reason"] == "gateway"
