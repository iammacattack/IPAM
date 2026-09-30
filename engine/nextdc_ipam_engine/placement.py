"""Host placement matrix (spec §5.6 point 3, FR-11a).

For a template version, every fixed host-pool member is resolved against every
VLAN it can live on that the template binds. The matrix is the release gate:
any conflict blocks ``:release``. Calculated or supernet placements only warn.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from .errors import EngineError
from .hosts import HostPosition, resolve_host
from .template import Layout


@dataclass
class PoolMember:
    name: str
    kind: str  # fixed | range | reserved
    position: HostPosition | None = None
    secondary_octet: int | None = None
    range_start: int | None = None
    range_end: int | None = None


@dataclass
class HostPool:
    role_code: str
    vlan_keys: list[str]
    members: list[PoolMember]
    offset_mode: str = "literalOctet"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HostPool":
        members = []
        for m in d.get("members", []):
            kind = m.get("kind", "fixed")
            members.append(
                PoolMember(
                    name=m["name"],
                    kind=kind,
                    position=HostPosition.parse(m["hostPosition"]) if m.get("hostPosition") is not None else None,
                    secondary_octet=m.get("secondaryHostOctet"),
                    range_start=m.get("rangeStart"),
                    range_end=m.get("rangeEnd"),
                )
            )
        return cls(d["roleCode"], list(d.get("vlanKeys", [])), members, d.get("offsetMode", "literalOctet"))


@dataclass
class Placement:
    role_code: str
    member: str
    vlan_key: str
    subnet: IPv4Network
    host_position: str
    ip: IPv4Address | None
    octet_used: str | None
    warnings: list[str] = field(default_factory=list)
    conflict: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "roleCode": self.role_code,
            "member": self.member,
            "vlanKey": self.vlan_key,
            "subnet": str(self.subnet),
            "hostPosition": self.host_position,
            "ip": str(self.ip) if self.ip else None,
            "octetUsed": self.octet_used,
            "warnings": self.warnings,
            "conflict": self.conflict,
        }


def place_members(
    subnets_by_vlan: dict[str, tuple[IPv4Network, IPv4Address]],
    pools: list[HostPool],
    *,
    avoid_zero_and_broadcast_in_supernets: bool = True,
) -> list[Placement]:
    """Resolve every fixed member on every VLAN it lives on.

    ``subnets_by_vlan`` maps vlanKey -> (subnet, gateway). Works on relative or
    absolute subnets alike, which is why the same code serves release (relative)
    and deploy (absolute).
    """
    out: list[Placement] = []
    for pool in pools:
        for vlan_key in pool.vlan_keys:
            if vlan_key not in subnets_by_vlan:
                continue
            subnet, gateway = subnets_by_vlan[vlan_key]
            for m in pool.members:
                if m.kind != "fixed" or m.position is None:
                    continue
                p = Placement(pool.role_code, m.name, vlan_key, subnet, str(m.position), None, None)
                try:
                    r = resolve_host(
                        subnet,
                        m.position,
                        secondary_octet=m.secondary_octet,
                        offset_mode=pool.offset_mode,
                        gateway=gateway,
                        avoid_zero_and_broadcast_in_supernets=avoid_zero_and_broadcast_in_supernets,
                        member=m.name,
                    )
                    p.ip, p.octet_used, p.warnings = r.ip, r.octet_used, r.warnings
                    if r.octet_used == "calculated":
                        p.warnings = p.warnings + ["resolved by calculated fallback"]
                except EngineError as err:
                    p.conflict = err.to_dict()
                out.append(p)

    # Two members landing on the same address on one VLAN is a conflict, not a silent bump.
    by_addr: dict[tuple[str, IPv4Address], list[Placement]] = {}
    for p in out:
        if p.ip is not None:
            by_addr.setdefault((p.vlan_key, p.ip), []).append(p)
    for (vlan_key, ip), group in by_addr.items():
        if len(group) > 1:
            names = [f"{g.role_code}/{g.member}" for g in group]
            for g in group:
                g.conflict = {
                    "code": "IPAM-HOST-COLLISION",
                    "message": f"{', '.join(names)} all resolve to {ip} on {vlan_key}",
                    "members": names,
                }
    return out


def placement_matrix(layout: Layout, pools: list[HostPool], **kwargs: Any) -> list[Placement]:
    by_vlan: dict[str, tuple[IPv4Network, IPv4Address]] = {}
    for s in layout.subnets:
        if s.vlan_key:
            by_vlan[s.vlan_key] = (s.relative, s.relative.network_address + s.gateway_offset)
    return place_members(by_vlan, pools, **kwargs)
