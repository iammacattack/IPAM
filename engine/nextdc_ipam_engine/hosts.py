"""Host addressing (spec §5.6, "Host addressing model (v0.8)").

A host-pool member has a two-part position ``index.octet`` (``0.61``, ``1.10``).
On any VLAN subnet it resolves to exactly one address, trying in order:

1. primary   - VLAN 3OCT (+ index) with the literal host octet
2. secondary - the same with the member's explicit secondary octet, if set
3. calculated - network + ((index * 256 + octet) mod subnet size)

The first *usable* candidate wins; if none is usable it's IPAM-HOST-OCTET-CONFLICT.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Iterable

from .errors import EngineError


@dataclass(frozen=True)
class HostPosition:
    index: int
    octet: int

    @classmethod
    def parse(cls, raw: str | int) -> "HostPosition":
        text = str(raw).strip()
        parts = text.split(".")
        try:
            if len(parts) == 1:
                index, octet = 0, int(parts[0])
            elif len(parts) == 2:
                index, octet = int(parts[0]), int(parts[1])
            else:
                raise ValueError
        except ValueError as exc:
            raise EngineError("IPAM-HOST-POSITION-INVALID", f"'{raw}' isn't a host position like 61 or 1.10") from exc
        if index < 0 or not (0 <= octet <= 255):
            raise EngineError("IPAM-HOST-POSITION-INVALID", f"'{raw}': index must be >= 0 and octet 0-255")
        return cls(index, octet)

    def __str__(self) -> str:
        return f"{self.index}.{self.octet}"


@dataclass
class Resolution:
    ip: IPv4Address
    octet_used: str  # primary | secondary | calculated
    candidates: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def is_supernet(subnet: IPv4Network) -> bool:
    return subnet.prefixlen < 24


def third_octet_span(subnet: IPv4Network) -> int:
    return 2 ** (24 - subnet.prefixlen) if is_supernet(subnet) else 1


def unusable_reason(
    ip: IPv4Address,
    subnet: IPv4Network,
    *,
    gateway: IPv4Address | None = None,
    taken: Iterable[IPv4Address] = (),
    avoid_zero_and_broadcast_in_supernets: bool = True,
) -> str | None:
    """Why ``ip`` can't be used as a host address in ``subnet`` (None if it can)."""
    if ip not in subnet:
        return "outside-subnet"
    if ip == subnet.network_address:
        return "network-address"
    if ip == subnet.broadcast_address:
        return "broadcast-address"
    if gateway is not None and ip == gateway:
        return "gateway"
    if ip in set(taken):
        return "taken"
    if avoid_zero_and_broadcast_in_supernets and is_supernet(subnet) and int(ip) & 0xFF in (0, 255):
        # Valid hosts inside a supernet, but some OT devices mishandle them.
        return "zero-or-255-in-supernet"
    return None


def _literal(subnet: IPv4Network, index: int, octet: int) -> tuple[IPv4Address | None, str | None]:
    base3 = int(subnet.network_address) & ~0xFF
    return IPv4Address(base3 + index * 256 + octet), None


def _check_index(subnet: IPv4Network, position: HostPosition, member: str | None) -> None:
    """An index outside the subnet's third-octet span is a configuration error, not a fallback case."""
    span = third_octet_span(subnet)
    if position.index >= span:
        where = f"this /{subnet.prefixlen} spans {span} third octet(s)" if is_supernet(subnet) else "the index must be 0 on a /24 or smaller"
        raise EngineError(
            "IPAM-HOST-POSITION-INVALID",
            f"{member or 'host'} position {position} doesn't fit {subnet}: {where}",
            member=member,
            subnet=str(subnet),
            hostPosition=str(position),
        )


def resolve_host(
    subnet: IPv4Network,
    position: HostPosition,
    *,
    secondary_octet: int | None = None,
    offset_mode: str = "literalOctet",
    gateway: IPv4Address | None = None,
    taken: Iterable[IPv4Address] = (),
    avoid_zero_and_broadcast_in_supernets: bool = True,
    member: str | None = None,
) -> Resolution:
    _check_index(subnet, position, member)
    taken_set = set(taken)
    candidates: list[dict] = []

    def check(label: str, ip: IPv4Address | None, pre_reason: str | None = None) -> Resolution | None:
        reason = pre_reason or unusable_reason(
            ip,  # type: ignore[arg-type]
            subnet,
            gateway=gateway,
            taken=taken_set,
            avoid_zero_and_broadcast_in_supernets=avoid_zero_and_broadcast_in_supernets,
        )
        candidates.append({"candidate": label, "ip": str(ip) if ip else None, "reason": reason})
        return None if reason else Resolution(ip, label, candidates)  # type: ignore[arg-type]

    order: list[tuple[str, IPv4Address | None, str | None]] = []
    if offset_mode == "literalOctet":
        order.append(("primary", *_literal(subnet, position.index, position.octet)))
        if secondary_octet is not None:
            order.append(("secondary", *_literal(subnet, position.index, secondary_octet)))
    elif offset_mode != "fromNetwork":
        raise EngineError("IPAM-TEMPLATE-INVALID", f"unknown offsetMode '{offset_mode}'")
    size = subnet.num_addresses
    calc = IPv4Address(int(subnet.network_address) + ((position.index * 256 + position.octet) % size))
    order.append(("calculated", calc, None))

    for label, ip, pre in order:
        res = check(label, ip, pre)
        if res:
            res.warnings = placement_warnings(subnet)
            return res

    raise EngineError(
        "IPAM-HOST-OCTET-CONFLICT",
        f"{member or 'host'} at position {position} has no usable address in {subnet}",
        member=member,
        subnet=str(subnet),
        hostPosition=str(position),
        candidates=candidates,
    )


def placement_warnings(subnet: IPv4Network) -> list[str]:
    """Design guidance (spec §5.6 point 4): warn, never block."""
    if is_supernet(subnet):
        return ["fixed host on a supernet; prefer /24 or lower-/25 VLANs for fixed roles"]
    if subnet.prefixlen > 24 and int(subnet.network_address) & 0xFF:
        return ["fixed host on a subnet that doesn't start at .0 of its /24; the literal octet may not fit"]
    return []
