"""VLAN attribute lookup (spec §8.2.1, FR-10a).

Field names follow the Site Delivery Wizard token vocabulary so its
``[Vlan.NAME.3OCT|Mask|Prefix|Gateway]`` tokens map one-to-one.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Any, Iterable

from .errors import EngineError
from .hosts import is_supernet, third_octet_span, unusable_reason

# dnsServers, vlanId and vlanName need data the engine doesn't hold; the API adds them.
NETWORK_FIELDS = (
    "gateway",
    "mask",
    "prefix",
    "cidr",
    "network",
    "networkPortion",
    "twoOctets",
    "spansThirdOctets",
    "broadcast",
    "firstUsable",
    "lastUsable",
)
ALL_FIELDS = NETWORK_FIELDS + ("vlanId", "vlanName", "dnsServers", "validateOctet")


def _octets(ip: IPv4Address, n: int) -> str:
    return ".".join(str(ip).split(".")[:n])


def network_portion(subnet: IPv4Network, index: int | None = None) -> str:
    """3OCT: mask-independent first three octets; on a supernet, of the index-th /24."""
    idx = index or 0
    span = third_octet_span(subnet)
    if idx < 0 or idx >= span:
        raise EngineError(
            "IPAM-INDEX-OUT-OF-RANGE",
            f"index {idx} is outside {subnet} (valid 0-{span - 1})",
            subnet=str(subnet),
        )
    base3 = int(subnet.network_address) & ~0xFF
    return _octets(IPv4Address(base3 + idx * 256), 3)


def spans_third_octets(subnet: IPv4Network) -> str:
    first = (int(subnet.network_address) >> 8) & 0xFF
    if not is_supernet(subnet):
        return str(first)
    # ASCII hyphen rather than the spec's en dash, so the value is safe in shell scripts.
    return f"{first}-{first + third_octet_span(subnet) - 1}"


def vlan_attributes(subnet: IPv4Network, gateway: IPv4Address, index: int | None = None) -> dict[str, Any]:
    hosts_first = subnet.network_address + 1
    hosts_last = subnet.broadcast_address - 1
    return {
        "gateway": str(gateway),
        "mask": str(subnet.netmask),
        "prefix": subnet.prefixlen,
        "cidr": str(subnet),
        "network": str(subnet.network_address),
        "networkPortion": network_portion(subnet, index),
        "twoOctets": _octets(subnet.network_address, 2),
        "spansThirdOctets": spans_third_octets(subnet),
        "broadcast": str(subnet.broadcast_address),
        "firstUsable": str(hosts_first),
        "lastUsable": str(hosts_last),
    }


def validate_octet(
    subnet: IPv4Network,
    gateway: IPv4Address,
    octet: int,
    *,
    index: int = 0,
    taken: Iterable[IPv4Address] = (),
    avoid_zero_and_broadcast_in_supernets: bool = True,
) -> dict[str, Any]:
    """Can a client append ``octet`` to this VLAN's 3OCT and get a usable host?"""
    if not (0 <= octet <= 255):
        raise EngineError("IPAM-HOST-POSITION-INVALID", "octet must be 0-255")
    portion = network_portion(subnet, index)
    ip = IPv4Address(f"{portion}.{octet}")
    reason = unusable_reason(
        ip,
        subnet,
        gateway=gateway,
        taken=taken,
        avoid_zero_and_broadcast_in_supernets=avoid_zero_and_broadcast_in_supernets,
    )
    return {"ip": str(ip), "usable": reason is None, "reason": reason}
